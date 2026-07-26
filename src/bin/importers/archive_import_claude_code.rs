//! Claude Code (`.claude` JSONL) importer — block-DAG projection.
//!
//! Each JSONL record becomes one **block** in the perception/action DAG
//! ([`faculties::schemas::blockdag`]); each content block inside a record's
//! `message.content` becomes a **content-fact** owned by that block via
//! [`block::contains`]. `parentUuid` resolves to [`block::previous`]; the
//! record `type` (`user`/`assistant`) plus the content block type set each
//! content-fact's [`content_fact::direction`] (the training loss mask).
//!
//! The projection is a *streaming projection*: it scans only the fields it
//! needs out of each JSONL line with [`triblespace::core::import::scanner`]
//! and never materializes a `serde_json::Value` tree. This replaces the old
//! `serde_json::Value` + `MessageRecord` + `JsonTreeImporter` path (which
//! allocated several times the source size per record — a cold `~/.claude`
//! import reached 57.9 GB resident, 2026-07-26).
//!
//! Phase 1 delivered the core block/content-fact projection with a strict
//! two-pass `entity!` discipline. Phase 2 added the tool-correlator →
//! [`content_fact::responds_to`] edge, image/media content-facts (inline
//! base64 → [`content_fact::blob`], other sources → the keep-the-pointer
//! branch of the resolution law), and the `author`/`experiencer` roster
//! links via [`RosterIndex`]. Phase 3 (this file) resolves cross-file
//! `previous` edges deterministically: a cheap parallel PRE-SCAN reads only
//! `uuid`/`parentUuid` per line, [`compute_waves`] partitions the corpus
//! into dependency-ordered waves from that pre-scan alone, and each wave
//! projects in parallel against a read-only [`UuidSnapshot`] of everything
//! earlier waves defined — so block ids never depend on scheduling (see the
//! determinism argument at the `previous` resolution site in
//! [`project_record`]).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::common;
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use faculties::schemas::relations as relations_schema;
use hifitime::Epoch;
use tracing::info_span;
use triblespace::core::blob::Bytes;
use triblespace::core::import::scanner as sc;
use triblespace::prelude::blobencodings::{LongString, RawBytes};
use triblespace::prelude::inlineencodings::U256BE;
use triblespace::prelude::*;

#[derive(Debug, Default, Clone)]
struct ImportStats {
    files: usize,
    blocks: usize,
    content_facts: usize,
    commits: usize,
    resolution: ProjectionStats,
    /// Files projected per dependency-ordered wave (directory imports only;
    /// empty for a single-file import).
    wave_files: Vec<usize>,
    /// Files whose external refs never became resolvable (truly dangling or
    /// cyclic) — projected in the final pass after all waves.
    final_pass_files: usize,
}

/// Reference-resolution counters for one projection (per file, then summed).
/// Every dangling reference is counted and logged — never silently dropped.
#[derive(Debug, Default, Clone, Copy)]
struct ProjectionStats {
    /// `tool_result` correlators with no preceding `tool_use` in the same
    /// file — the `responds_to` edge is dropped.
    dangling_correlators: usize,
    /// `parentUuid`s that resolved nowhere — neither in this file nor in the
    /// wave snapshot. After phase 3 this means the uuid is defined in no file
    /// at all (truly dangling) or only inside a mutual-reference cycle
    /// projected in the final pass; the `previous` edge is dropped.
    cross_file_parents: usize,
    /// `parentUuid`s naming a non-dialogue line (system/progress/…) — in this
    /// file or, via the wave snapshot, in an earlier wave's file — the parent
    /// projects no block, so the edge has no target.
    skipped_parents: usize,
    /// Cross-file `previous` edges resolved through the wave snapshot
    /// (phase 3). A success counter, not a gap — excluded from [`Self::total`].
    cross_file_resolved: usize,
    /// Image sources that could not be projected (bad base64, missing data
    /// or pointer).
    undecodable_images: usize,
    /// `direction = out ⟺ author == experiencer` consistency-check failures.
    invariant_breaches: usize,
}

impl ProjectionStats {
    fn absorb(&mut self, other: ProjectionStats) {
        self.dangling_correlators += other.dangling_correlators;
        self.cross_file_parents += other.cross_file_parents;
        self.skipped_parents += other.skipped_parents;
        self.cross_file_resolved += other.cross_file_resolved;
        self.undecodable_images += other.undecodable_images;
        self.invariant_breaches += other.invariant_breaches;
    }

    fn total(&self) -> usize {
        self.dangling_correlators
            + self.cross_file_parents
            + self.skipped_parents
            + self.undecodable_images
            + self.invariant_breaches
    }
}

/// One projected file: its self-contained fragment, resolution counters, and
/// the uuid exports the wave scheduler merges into the global
/// [`UuidSnapshot`] after the file's wave completes.
struct Projected {
    fragment: Fragment,
    stats: ProjectionStats,
    /// Every dialogue-line uuid this file defined → its block id.
    uuid_to_block: HashMap<String, Id>,
    /// Every non-dialogue (system/progress/…) uuid this file defined — a
    /// cross-file `parentUuid` into one of these classifies as
    /// skipped-parent, not dangling.
    skipped_uuids: HashSet<String>,
}

/// Label → participant-entity index over a `relations` roster snapshot.
///
/// Keys are the roster's normalized lookup labels ([`relations_schema::relations::label_norm`]
/// plus `alias_norm`; canonical labels win over a colliding alias). `face`
/// names the being's own participant entity for this import stream — the
/// author AND experiencer of every `out` block, and the experiencer of `in`
/// blocks. Wiring the real roster (and the face label) into the entry point
/// is the caller's job; the importer only consumes `Option<&RosterIndex>`.
pub struct RosterIndex {
    by_label: HashMap<String, Id>,
    face: Option<Id>,
}

impl RosterIndex {
    /// Build from relations facts, resolving `face_label` (the being's own
    /// roster label) through the same index.
    #[allow(dead_code)] // constructed by the caller wiring in the real roster
    pub fn build(roster: &TribleSet, face_label: Option<&str>) -> Self {
        let mut by_label: HashMap<String, Id> = HashMap::new();
        for (person, alias) in find!(
            (person: Id, alias: String),
            pattern!(roster, [{ ?person @
                common::metadata::tag: relations_schema::KIND_PERSON_ID,
                relations_schema::relations::alias_norm: ?alias,
            }])
        ) {
            by_label.insert(Self::normalize(&alias), person);
        }
        // Canonical labels second, so they win over a colliding alias.
        for (person, label) in find!(
            (person: Id, label: String),
            pattern!(roster, [{ ?person @
                common::metadata::tag: relations_schema::KIND_PERSON_ID,
                relations_schema::relations::label_norm: ?label,
            }])
        ) {
            by_label.insert(Self::normalize(&label), person);
        }
        let face = face_label.and_then(|label| by_label.get(&Self::normalize(label)).copied());
        RosterIndex { by_label, face }
    }

    fn normalize(label: &str) -> String {
        label.trim().to_ascii_lowercase()
    }

    /// Resolve a raw source-author label to a roster participant.
    fn resolve(&self, label: &str) -> Option<Id> {
        self.by_label.get(&Self::normalize(label)).copied()
    }

    /// The being's own participant entity for this import stream.
    fn face(&self) -> Option<Id> {
        self.face
    }
}

fn import_claude_code_path(
    path: &Path,
    repo: &mut common::Repo,
    branch_id: Id,
    roster: Option<&RosterIndex>,
) -> Result<ImportStats> {
    let start = Instant::now();
    println!("claude-code phase pull: {}", path.display());
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
    let mut catalog = ws.checkout(..).context("checkout workspace")?.into_facts();
    let mut catalog_head = ws.head();
    println!("claude-code phase pull: done in {:?}", start.elapsed());

    if path.is_dir() {
        let scan_start = Instant::now();
        println!("claude-code phase scan: {}", path.display());
        let mut paths = Vec::new();
        collect_jsonl_files(path, &mut paths)
            .with_context(|| format!("scan {}", path.display()))?;
        paths.sort();
        println!(
            "claude-code phase scan: found {} jsonl file(s) under {} in {:?}",
            paths.len(),
            path.display(),
            scan_start.elapsed()
        );
        return import_directory_waves(
            &paths,
            roster,
            repo,
            &mut ws,
            &mut catalog,
            &mut catalog_head,
        );
    }

    let parse_start = Instant::now();
    println!("claude-code phase parse: {}", path.display());
    let projected = parse_jsonl(path, roster, None)?;
    println!(
        "claude-code phase parse: projected {} trible(s) in {:?}",
        projected.fragment.facts().len(),
        parse_start.elapsed()
    );
    let Projected {
        fragment,
        stats: resolution,
        ..
    } = projected;
    import_claude_code_records(
        path,
        fragment,
        resolution,
        repo,
        &mut ws,
        &mut catalog,
        &mut catalog_head,
    )
}

/// Directory import via the phase-3 WAVE-FIXPOINT scheduler — the
/// dependency-ordered projection the phase-2 analysis called for.
///
/// 1. PRE-SCAN (parallel, cheap): every file yields its defined uuids and
///    external refs ([`prescan_file`]).
/// 2. [`compute_waves`] partitions the corpus into waves from the pre-scan
///    alone; wave 1 = files with no external refs.
/// 3. Each wave projects in parallel through the existing bounded-backpressure
///    machinery ([`common::parse_paths_streaming`]) against a READ-ONLY
///    [`UuidSnapshot`] frozen for the whole wave; the sequential committer
///    commits each file as its projection arrives, exactly as before. After
///    the wave, every file's uuid exports merge into the snapshot in sorted
///    path order (first binding wins), so the merge — like the partition — is
///    independent of within-wave completion order.
/// 4. Files that never become eligible (refs to uuids defined nowhere, or
///    mutual-reference cycles) project LAST with the final snapshot; their
///    unresolved refs count as truly dangling.
fn import_directory_waves(
    paths: &[PathBuf],
    roster: Option<&RosterIndex>,
    repo: &mut common::Repo,
    ws: &mut common::Ws,
    catalog: &mut TribleSet,
    catalog_head: &mut Option<common::CommitHandle>,
) -> Result<ImportStats> {
    // ── pre-scan: uuid definitions/references only ──────────────────────
    let prescan_start = Instant::now();
    let prescanned = common::parse_paths_parallel("claude-code pre-scan", paths, prescan_file)?;
    let mut prescans = Vec::with_capacity(prescanned.len());
    for (file, res) in prescanned {
        prescans.push(res.with_context(|| format!("pre-scan {}", file.display()))?);
    }
    let (waves, unresolvable) = compute_waves(&prescans);
    drop(prescans);
    println!(
        "claude-code phase schedule: {} wave(s){} in {:?}",
        waves.len(),
        if unresolvable.is_empty() {
            String::new()
        } else {
            format!(
                ", {} file(s) deferred to the final pass",
                unresolvable.len()
            )
        },
        prescan_start.elapsed()
    );

    let mut total = ImportStats::default();
    total.wave_files = waves.iter().map(Vec::len).collect();
    total.final_pass_files = unresolvable.len();
    let total_files = paths.len();
    let wave_count = waves.len();
    let mut files_done = 0usize;
    let mut snapshot = UuidSnapshot::default();

    let mut passes: Vec<(String, Vec<usize>)> = waves
        .into_iter()
        .enumerate()
        .map(|(i, wave)| (format!("wave {}/{wave_count}", i + 1), wave))
        .collect();
    if !unresolvable.is_empty() {
        passes.push(("final pass".to_string(), unresolvable));
    }

    // Bounded in-flight parses. `parse_paths_streaming` runs the whole
    // per-file projection (scan + `entity!`) on the parser threads and hands
    // each finished `Fragment` to the sequential committer as it arrives,
    // never holding more than PARSE_IN_FLIGHT projected files at once. Kept
    // small deliberately — a single transcript can be 2 GB.
    const PARSE_IN_FLIGHT: usize = 4;
    for (pass_label, indices) in passes {
        let wave_paths: Vec<PathBuf> = indices.iter().map(|&i| paths[i].clone()).collect();
        println!("claude-code {pass_label}: {} file(s)", wave_paths.len());
        // Uuid exports of this wave's files, merged only AFTER the wave — a
        // projection consults exactly its wave's frozen snapshot.
        let mut wave_exports: Vec<(PathBuf, HashMap<String, Id>, HashSet<String>)> =
            Vec::with_capacity(wave_paths.len());
        let snapshot_ref = &snapshot;
        let stream_label = format!("claude-code {pass_label}");
        common::parse_paths_streaming(
            &stream_label,
            &wave_paths,
            PARSE_IN_FLIGHT,
            |file: &Path| parse_jsonl(file, roster, Some(snapshot_ref)),
            |_, file, parsed| {
                files_done += 1;
                let file_start = Instant::now();
                println!(
                    "claude-code file {files_done}/{total_files} ({pass_label}): {}",
                    file.display()
                );
                let projected = parsed.with_context(|| format!("parse {}", file.display()))?;
                let dangling =
                    projected.stats.cross_file_parents + projected.stats.skipped_parents;
                if dangling > 0 {
                    eprintln!(
                        "claude-code: {} unresolved parentUuid(s) in {} \
                         ({} truly dangling, {} to skipped lines) — previous edges dropped",
                        dangling,
                        file.display(),
                        projected.stats.cross_file_parents,
                        projected.stats.skipped_parents,
                    );
                }
                let Projected {
                    fragment,
                    stats: resolution,
                    uuid_to_block,
                    skipped_uuids,
                } = projected;
                wave_exports.push((file.clone(), uuid_to_block, skipped_uuids));
                if fragment.facts().is_empty() {
                    total.resolution.absorb(resolution);
                    return Ok(());
                }
                let stats = import_claude_code_records(
                    &file,
                    fragment,
                    resolution,
                    repo,
                    ws,
                    catalog,
                    catalog_head,
                )
                .with_context(|| format!("import {}", file.display()))?;
                total.files += stats.files;
                total.blocks += stats.blocks;
                total.content_facts += stats.content_facts;
                total.commits += stats.commits;
                total.resolution.absorb(stats.resolution);
                println!(
                    "claude-code progress files {}/{} (blocks {}, content-facts {}, commits {}) in {:?}",
                    files_done, total_files, total.blocks, total.content_facts, total.commits,
                    file_start.elapsed()
                );
                Ok(())
            },
        )?;
        // Deterministic merge: sorted path order, first binding wins — never
        // the order the parser threads happened to finish in.
        wave_exports.sort_by(|a, b| a.0.cmp(&b.0));
        for (_, uuid_to_block, skipped_uuids) in wave_exports {
            for (uuid, block) in uuid_to_block {
                snapshot.blocks.entry(uuid).or_insert(block);
            }
            snapshot.skipped.extend(skipped_uuids);
        }
    }
    Ok(total)
}

/// Stage a projected file's blobs into the workspace and commit its facts.
///
/// The heavy work (scan + content-addressed `entity!` projection) already
/// happened in [`parse_jsonl`] on a parser thread; this sequential step owns
/// `&mut Workspace`, so it only merges the fragment's self-contained blob
/// store into the staging area and commits the delta.
fn import_claude_code_records(
    _path: &Path,
    fragment: Fragment,
    resolution: ProjectionStats,
    repo: &mut common::Repo,
    ws: &mut common::Ws,
    catalog: &mut TribleSet,
    catalog_head: &mut Option<common::CommitHandle>,
) -> Result<ImportStats> {
    let mut stats = ImportStats {
        files: 1,
        resolution,
        ..ImportStats::default()
    };

    {
        let facts = fragment.facts();
        stats.blocks = find!(
            (block: Id),
            pattern!(facts, [{ ?block @ common::metadata::tag: common::block::KIND }])
        )
        .count();
        stats.content_facts = find!(
            (cf: Id),
            pattern!(facts, [{ ?cf @ common::metadata::tag: common::content_fact::KIND }])
        )
        .count();
    }

    // The projection put every referenced payload/label/signature blob into
    // the fragment's own MemoryBlobStore; merge them into the workspace's
    // staging area so the commit ships them alongside the facts.
    let (facts, blobs) = fragment.into_facts_and_blobs();
    ws.staged.union(blobs);

    if common::commit_delta(
        repo,
        ws,
        catalog,
        catalog_head,
        facts,
        "import claude-code block-dag",
    )? {
        stats.commits += 1;
    }

    Ok(stats)
}

// ---------------------------------------------------------------------------
// Wave scheduling — deterministic cross-file `previous` (phase 3)
// ---------------------------------------------------------------------------

/// Read-only cross-file uuid resolutions a projection may consult, frozen for
/// one whole wave. Grows only BETWEEN waves (deterministic merge in
/// [`import_directory_waves`]), never during one.
#[derive(Debug, Default)]
struct UuidSnapshot {
    /// uuid → block id, for every dialogue line earlier waves projected.
    blocks: HashMap<String, Id>,
    /// uuids earlier waves defined but skipped (non-dialogue lines) — a
    /// `parentUuid` into one of these is a skipped-parent, not dangling.
    skipped: HashSet<String>,
}

/// Pre-scanned uuid surface of one file: every line uuid it defines
/// (dialogue or not) and every `parentUuid` naming no uuid defined in the
/// same file.
#[derive(Debug, Default)]
struct PreScan {
    defined: HashSet<String>,
    external_refs: HashSet<String>,
}

/// Partition file indices into dependency-ordered waves, purely from the
/// pre-scan.
///
/// A file is eligible for the next wave when every external ref names a uuid
/// DEFINED by a file scheduled in an earlier wave — whether that line
/// projects a block or is a skipped non-dialogue line; the snapshot
/// classification at projection time distinguishes the two. Wave 1 = files
/// with no external refs. Files that never become eligible (refs to uuids
/// defined in no file, or mutual-reference cycles — cycle members are never
/// eligible because each waits on the other, so the loop terminates instead
/// of deadlocking) are returned separately for the final pass. No projection
/// output and no scheduling order feeds back into the partition.
fn compute_waves(prescans: &[PreScan]) -> (Vec<Vec<usize>>, Vec<usize>) {
    let mut scheduled_defs: HashSet<&str> = HashSet::new();
    let mut remaining: Vec<usize> = (0..prescans.len()).collect();
    let mut waves: Vec<Vec<usize>> = Vec::new();
    loop {
        let (eligible, rest): (Vec<usize>, Vec<usize>) =
            std::mem::take(&mut remaining).into_iter().partition(|&i| {
                prescans[i]
                    .external_refs
                    .iter()
                    .all(|r| scheduled_defs.contains(r.as_str()))
            });
        if eligible.is_empty() {
            return (waves, rest);
        }
        for &i in &eligible {
            scheduled_defs.extend(prescans[i].defined.iter().map(String::as_str));
        }
        waves.push(eligible);
        remaining = rest;
    }
}

/// Cheap pre-scan of one file: only `uuid`/`parentUuid` per line.
fn prescan_file(path: &Path) -> Result<PreScan> {
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let bytes = Bytes::from_source(data);
    prescan_jsonl(&bytes).with_context(|| format!("pre-scan {}", path.display()))
}

/// The projecting-scanner's cheap path: per line, parse only `uuid` and
/// `parentUuid`, [`sc::skip_value`] everything else (message bodies
/// included — nothing is materialized).
fn prescan_jsonl(bytes: &Bytes) -> Result<PreScan> {
    let mut defined: HashSet<String> = HashSet::new();
    let mut refs: HashSet<String> = HashSet::new();
    for_each_jsonl_line(bytes, |line| {
        let (uuid, parent) = prescan_record(line)
            .map_err(|e| anyhow!("pre-scan claude-code jsonl record: {e}"))?;
        if let Some(uuid) = uuid {
            defined.insert(uuid);
        }
        if let Some(parent) = parent {
            refs.insert(parent);
        }
        Ok(())
    })?;
    let external_refs = refs
        .into_iter()
        .filter(|r| !defined.contains(r))
        .collect();
    Ok(PreScan {
        defined,
        external_refs,
    })
}

/// Scan one record for `(uuid, parentUuid)`, skipping every other value.
fn prescan_record(line: &mut Bytes) -> Result<(Option<String>, Option<String>), sc::ScanError> {
    let mut ids: (Option<String>, Option<String>) = (None, None);
    sc::object(line, &mut ids, |ids, key, value| {
        let key = key
            .view::<str>()
            .map_err(|_| scan_syntax("invalid utf-8 key"))?;
        match key.as_ref() {
            "uuid" => ids.0 = parse_opt_str(value)?,
            "parentUuid" => ids.1 = parse_opt_str(value)?,
            _ => sc::skip_value(value)?,
        }
        Ok(ids)
    })?;
    Ok(ids)
}

// ---------------------------------------------------------------------------
// Parsing + projection
// ---------------------------------------------------------------------------

/// Read a `.claude` JSONL file and project it onto the block-DAG schema,
/// returning a self-contained [`Fragment`] (facts + the blobs they reference).
///
/// Runs on the parser threads of [`common::parse_paths_streaming`]. The
/// projection is content-addressed and side-effect-free — no workspace, no
/// pile, and the wave `snapshot` is read-only — so it is safe to run off the
/// committing thread.
fn parse_jsonl(
    path: &Path,
    roster: Option<&RosterIndex>,
    snapshot: Option<&UuidSnapshot>,
) -> Result<Projected> {
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let bytes = Bytes::from_source(data);
    project_jsonl(&bytes, roster, snapshot).with_context(|| format!("project {}", path.display()))
}

/// Split `bytes` into JSONL lines — trimming ASCII whitespace (including a
/// trailing `\r`) so the scanner sees the record's opening `{` as the first
/// byte — and hand each non-empty line to `f`. Shared by the full projection
/// and the pre-scan.
fn for_each_jsonl_line<F>(bytes: &Bytes, mut f: F) -> Result<()>
where
    F: FnMut(&mut Bytes) -> Result<()>,
{
    let raw = bytes.as_ref();
    let len = raw.len();
    let mut start = 0usize;
    for i in 0..=len {
        let is_boundary = i == len || raw[i] == b'\n';
        if !is_boundary {
            continue;
        }
        if i > start {
            let seg = &raw[start..i];
            let first = seg.iter().position(|c| !c.is_ascii_whitespace());
            let last = seg.iter().rposition(|c| !c.is_ascii_whitespace());
            if let (Some(a), Some(z)) = (first, last) {
                let mut line = bytes.slice((start + a)..(start + z + 1));
                f(&mut line)?;
            }
        }
        start = i + 1;
    }
    Ok(())
}

/// Core projection: fold each JSONL line into the accumulating fragment.
///
/// Streams line-by-line — at most one [`RawRecord`] is alive at a time — so
/// peak memory is the raw file plus the growing fragment, never a per-record
/// dynamic JSON tree. `snapshot` is the wave scheduler's read-only cross-file
/// uuid map (None for a single-file import).
fn project_jsonl(
    bytes: &Bytes,
    roster: Option<&RosterIndex>,
    snapshot: Option<&UuidSnapshot>,
) -> Result<Projected> {
    let mut frag = Fragment::empty();
    let mut stats = ProjectionStats::default();
    // uuid → block id, so a record's `parentUuid` resolves to `block::previous`.
    let mut uuid_to_block: HashMap<String, Id> = HashMap::new();
    // uuids of non-dialogue lines (system, progress, …) that project no
    // block — used to classify a dangling `parentUuid` as "points at a
    // skipped line" rather than "unknown to this file".
    let mut skipped_uuids: HashSet<String> = HashSet::new();
    // vendor tool correlator (`toolu_…`) → tool_call content-fact id,
    // consumed by the `responds_to` edge resolution. tool_use always
    // precedes its tool_result in file order (the transcript is an
    // append-ordered log), so a single forward pass suffices — pinned by
    // `unresolved_correlator_is_counted_not_edged` in the tests.
    let mut correlator_to_cf: HashMap<String, Id> = HashMap::new();

    for_each_jsonl_line(bytes, |line| {
        let record =
            scan_record(line).map_err(|e| anyhow!("scan claude-code jsonl record: {e}"))?;
        project_record(
            &record,
            &mut frag,
            &mut uuid_to_block,
            &mut skipped_uuids,
            &mut correlator_to_cf,
            snapshot,
            roster,
            &mut stats,
        );
        Ok(())
    })?;

    Ok(Projected {
        fragment: frag,
        stats,
        uuid_to_block,
        skipped_uuids,
    })
}

/// Project one scanned record into the fragment (identity-core pass, then the
/// non-identity pass) for both its content-facts and the block itself.
fn project_record(
    record: &RawRecord,
    frag: &mut Fragment,
    uuid_to_block: &mut HashMap<String, Id>,
    skipped_uuids: &mut HashSet<String>,
    correlator_to_cf: &mut HashMap<String, Id>,
    snapshot: Option<&UuidSnapshot>,
    roster: Option<&RosterIndex>,
    stats: &mut ProjectionStats,
) {
    // Only user/assistant records are blocks. `user` is perceived (`in`),
    // `assistant` is produced (`out`); other line types (system, progress,
    // file-history-snapshot, …) are skipped — they carry no dialogue. Their
    // uuids are still recorded so a child's `parentUuid` into one of them is
    // classified as skipped-parent, not cross-file.
    let record_direction = match record.record_type.as_str() {
        "user" => common::content_fact::direction::in_,
        "assistant" => common::content_fact::direction::out_,
        _ => {
            if let Some(uuid) = &record.uuid {
                skipped_uuids.insert(uuid.clone());
            }
            return;
        }
    };

    let mut contained: Vec<Id> = Vec::new();
    for block in &record.blocks {
        // Resolve the tool correlator ONCE per tool_result, then drop the
        // string — it never persists and never enters any content-address.
        // The `answers-that` edge attaches to every content-fact this result
        // carries (its text and any embedded screenshot images).
        let responds_to = match block.kind {
            BlockKind::ToolResult => match &block.correlator {
                Some(correlator) => {
                    let resolved = correlator_to_cf.get(correlator).copied();
                    if resolved.is_none() {
                        stats.dangling_correlators += 1;
                        eprintln!(
                            "claude-code: tool_result correlator {correlator:?} has no \
                             tool_use in this file — responds_to edge dropped"
                        );
                    }
                    resolved
                }
                None => None,
            },
            _ => None,
        };

        // Textual content-fact (text/thinking/tool args/tool-result text).
        let text_fact = match block.kind {
            BlockKind::Text => Some((common::content_fact::modality::text, record_direction)),
            BlockKind::Thinking => Some((
                common::content_fact::modality::thinking,
                common::content_fact::direction::out_,
            )),
            BlockKind::ToolUse => Some((
                common::content_fact::modality::tool_call,
                common::content_fact::direction::out_,
            )),
            BlockKind::ToolResult => Some((
                common::content_fact::modality::tool_result,
                common::content_fact::direction::in_,
            )),
            BlockKind::Image | BlockKind::Other => None,
        };
        if let Some((modality, direction)) = text_fact {
            if !block.payload.trim().is_empty() {
                // Pass 1 — identity core (`_` mints the content-derived id).
                let payload = frag.put::<LongString, _>(block.payload.clone());
                let cf = entity! { _ @
                    common::content_fact::modality:  modality,
                    common::content_fact::direction: direction,
                    common::content_fact::payload:   payload,
                };
                let cf_id = cf
                    .root()
                    .expect("content_fact entity! must export a single root id");
                *frag += cf;

                // Pass 2 — non-identity facts on the same content-fact id.
                let signature = block
                    .signature
                    .as_ref()
                    .map(|s| frag.put::<LongString, _>(s.clone()));
                let cf_entity = ExclusiveId::force(cf_id);
                *frag += entity! { &cf_entity @
                    common::metadata::tag:          common::content_fact::KIND,
                    common::content_fact::signature?: signature,
                    common::content_fact::responds_to?: responds_to,
                };

                if let BlockKind::ToolUse = block.kind {
                    if let Some(correlator) = &block.correlator {
                        correlator_to_cf.insert(correlator.clone(), cf_id);
                    }
                }

                contained.push(cf_id);
            }
        }

        // Image content-facts: a top-level `image` block carries one; a
        // tool_result may carry several inside its content array (each an
        // ADDITIONAL fact on the same block, never spliced into the text).
        let image_direction = match block.kind {
            BlockKind::ToolResult => common::content_fact::direction::in_,
            _ => record_direction,
        };
        for image in &block.images {
            if let Some(cf_id) =
                project_image_fact(image, image_direction, responds_to, frag, stats)
            {
                contained.push(cf_id);
            }
        }
    }

    // Block identity core: {previous?, timestamp, contains-<cf ids>}.
    //
    // Cross-file `previous` (phase 3 — the dependency-ordered projection the
    // 2026-07-26 analysis called for): the local map resolves same-file
    // parents; on a miss, the wave scheduler's read-only `snapshot` resolves
    // cross-file parents. `previous` is identity-core, so this MUST be
    // deterministic — and it is, because a file only enters a wave once
    // every external ref's DEFINING file projected in an EARLIER wave
    // ([`compute_waves`]), so the snapshot a projection consults is frozen
    // per wave and never a function of within-wave completion order: block
    // ids converge run to run. Remaining misses classify as skipped (the
    // parent line projects no block — locally or in the snapshot's
    // defined-but-skipped set) or truly dangling (`cross_file_parents`: the
    // uuid is defined in no file, or only inside a mutual-reference cycle
    // projected in the final pass). A correct count beats a wrong edge.
    let timestamp =
        common::epoch_interval(record.timestamp.unwrap_or_else(common::unknown_epoch));
    let previous = match record.parent_uuid.as_ref() {
        None => None,
        Some(parent) => {
            let resolved = uuid_to_block.get(parent).copied().or_else(|| {
                let cross = snapshot.and_then(|s| s.blocks.get(parent).copied());
                if cross.is_some() {
                    stats.cross_file_resolved += 1;
                }
                cross
            });
            if resolved.is_none() {
                if skipped_uuids.contains(parent)
                    || snapshot.is_some_and(|s| s.skipped.contains(parent))
                {
                    stats.skipped_parents += 1;
                } else {
                    stats.cross_file_parents += 1;
                }
            }
            resolved
        }
    };
    let block = entity! { _ @
        common::block::timestamp: timestamp,
        common::block::previous?: previous,
        common::block::contains*: contained,
    };
    let block_id = block
        .root()
        .expect("block entity! must export a single root id");
    *frag += block;

    // Block non-identity pass: kind tag, raw author label, and — when a
    // roster is wired in and resolves — the typed author/experiencer links.
    let author_label = match record.record_type.as_str() {
        "assistant" => record
            .model
            .clone()
            .unwrap_or_else(|| "assistant".to_string()),
        other => other.to_string(),
    };
    let is_out = record_direction == common::content_fact::direction::out_;
    let (author, experiencer) = match roster {
        // Out-blocks are the being's own production: author = experiencer =
        // its face entity. In-blocks: the external participant authored what
        // the face experienced.
        Some(roster) if is_out => (roster.face(), roster.face()),
        Some(roster) => (roster.resolve(&author_label), roster.face()),
        None => (None, None),
    };
    // Import-time consistency check (logged, never a hard abort):
    // direction = out ⟺ author == experiencer.
    if let (Some(author), Some(experiencer)) = (author, experiencer) {
        if (author == experiencer) != is_out {
            stats.invariant_breaches += 1;
            eprintln!(
                "claude-code: author/experiencer invariant breach — {} block \
                 {block_id:x} has author {author:x}, experiencer {experiencer:x}",
                if is_out { "out" } else { "in" },
            );
        }
    }
    let source_author = frag.put::<LongString, _>(author_label);
    let block_entity = ExclusiveId::force(block_id);
    *frag += entity! { &block_entity @
        common::metadata::tag:                  common::block::KIND,
        common::import_schema::source_author:   source_author,
        common::import_schema::source_created_at: timestamp,
        common::block::author?:                 author,
        common::block::experiencer?:            experiencer,
        // TODO: retain `sessionId` / `parentUuid` as source-id provenance if
        // a raw-record round-trip is wanted.
    };

    if let Some(uuid) = &record.uuid {
        uuid_to_block.insert(uuid.clone(), block_id);
    }
}

/// Project one image source as a content-fact, per the resolution law:
/// inline base64 bytes become [`content_fact::blob`] (content-addressed, so
/// the same image seen through two exports stores once); any other source
/// keeps the reference itself as the fact via [`content_fact::asset_pointer`]
/// (+ mime/size), with bytes attachable later through `resolved_to` without
/// touching the id. Undecodable sources are counted and logged, never
/// silently dropped.
fn project_image_fact(
    image: &RawImageSource,
    direction: Id,
    responds_to: Option<Id>,
    frag: &mut Fragment,
    stats: &mut ProjectionStats,
) -> Option<Id> {
    // `asset_mime` is a ShortString (32-byte cap); a longer claimed mime is
    // dropped with a note rather than aborting the file.
    let mime = image.media_type.clone().filter(|m| {
        let fits = m.len() <= 32;
        if !fits {
            eprintln!("claude-code: image media_type {m:?} exceeds ShortString — dropped");
        }
        fits
    });
    let cf = if image.source_type == "base64" {
        let Some(data) = image.data.as_deref() else {
            stats.undecodable_images += 1;
            eprintln!("claude-code: base64 image source without data — skipped");
            return None;
        };
        let bytes = match BASE64_STANDARD.decode(data.as_bytes()) {
            Ok(bytes) => bytes,
            Err(err) => {
                stats.undecodable_images += 1;
                eprintln!("claude-code: undecodable base64 image ({err}) — skipped");
                return None;
            }
        };
        let blob = frag.put::<RawBytes, _>(bytes);
        entity! { _ @
            common::content_fact::modality:   common::content_fact::modality::image,
            common::content_fact::direction:  direction,
            common::content_fact::blob:       blob,
            common::content_fact::asset_mime?: mime,
        }
    } else {
        let Some(pointer) = image.pointer.clone() else {
            stats.undecodable_images += 1;
            eprintln!(
                "claude-code: image source type {:?} without url/file_id — skipped",
                image.source_type
            );
            return None;
        };
        let pointer = frag.put::<LongString, _>(pointer);
        let size: Option<Inline<U256BE>> = image.size.map(|s| s.to_inline());
        entity! { _ @
            common::content_fact::modality:      common::content_fact::modality::image,
            common::content_fact::direction:     direction,
            common::content_fact::asset_pointer: pointer,
            common::content_fact::asset_mime?:   mime,
            common::content_fact::asset_size?:   size,
        }
    };
    let cf_id = cf
        .root()
        .expect("content_fact entity! must export a single root id");
    *frag += cf;
    let cf_entity = ExclusiveId::force(cf_id);
    *frag += entity! { &cf_entity @
        common::metadata::tag:              common::content_fact::KIND,
        common::content_fact::responds_to?: responds_to,
    };
    Some(cf_id)
}

// ---------------------------------------------------------------------------
// Streaming scan — project only the fields the block-DAG needs
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RawRecord {
    record_type: String,
    uuid: Option<String>,
    parent_uuid: Option<String>,
    timestamp: Option<Epoch>,
    /// `message.model` (assistant records) — the raw author label.
    model: Option<String>,
    blocks: Vec<RawBlock>,
}

struct RawBlock {
    kind: BlockKind,
    /// Rendered-to-text payload: `text`/`thinking` verbatim, tool_use `input`
    /// as raw JSON, tool_result `content` as its textual content.
    payload: String,
    /// Vendor tool correlator: `id` (`toolu_…`) on tool_use, `tool_use_id` on
    /// tool_result. Resolved to the `responds_to` edge, then dropped.
    correlator: Option<String>,
    /// Claude's `thinking.signature` attestation (thinking blocks only).
    signature: Option<String>,
    /// Image sources this block carries: exactly one for a top-level `image`
    /// block, zero or more for a tool_result's embedded screenshots.
    images: Vec<RawImageSource>,
}

enum BlockKind {
    Text,
    Thinking,
    ToolUse,
    ToolResult,
    Image,
    Other,
}

/// One scanned image `source` object. `{"type":"base64","media_type":…,
/// "data":…}` is the inline branch; any other type (url / file pointer)
/// keeps its reference in `pointer` for the asset_pointer branch.
#[derive(Default)]
struct RawImageSource {
    source_type: String,
    media_type: Option<String>,
    /// Base64 payload (`source_type == "base64"`).
    data: Option<String>,
    /// External reference: `url` or `file_id`.
    pointer: Option<String>,
    /// Claimed byte size, when the source carries one.
    size: Option<u64>,
}

/// Fields of a single `message.content` block, gathered order-independently.
#[derive(Default)]
struct BlockAccum {
    btype: String,
    text: Option<String>,
    thinking: Option<String>,
    signature: Option<String>,
    tool_id: Option<String>,
    tool_use_id: Option<String>,
    input_raw: Option<String>,
    tool_result_content: Option<String>,
    tool_result_images: Vec<RawImageSource>,
    image_source: Option<RawImageSource>,
}

/// Fields projected out of the nested `message` object.
#[derive(Default)]
struct MessagePart {
    model: Option<String>,
    blocks: Vec<RawBlock>,
}

fn scan_syntax(message: &str) -> sc::ScanError {
    sc::ScanError::Syntax(message.to_owned())
}

/// Decode a scanned JSON string to an owned `String`.
fn bytes_to_string(bytes: Bytes) -> Result<String, sc::ScanError> {
    Ok(bytes
        .view::<str>()
        .map_err(|_| scan_syntax("invalid utf-8 string"))?
        .as_ref()
        .to_owned())
}

/// Parse a string value, or `None` for `null` / any non-string value (which is
/// skipped without materializing).
fn parse_opt_str(bytes: &mut Bytes) -> Result<Option<String>, sc::ScanError> {
    if bytes.first().copied() == Some(b'"') {
        Ok(Some(bytes_to_string(sc::parse_string(bytes)?)?))
    } else {
        sc::skip_value(bytes)?;
        Ok(None)
    }
}

/// Capture the raw JSON bytes of the value at the cursor (used to render a
/// tool_use `input` object to text losslessly), advancing past it.
fn capture_raw_json(bytes: &mut Bytes) -> Result<String, sc::ScanError> {
    let before = bytes.clone();
    sc::skip_value(bytes)?;
    let consumed = before.len() - bytes.len();
    let raw = before.slice(0..consumed);
    Ok(String::from_utf8_lossy(raw.as_ref()).into_owned())
}

fn scan_record(line: &mut Bytes) -> Result<RawRecord, sc::ScanError> {
    let mut record = RawRecord::default();
    sc::object(line, &mut record, |record, key, value| {
        let key = key
            .view::<str>()
            .map_err(|_| scan_syntax("invalid utf-8 key"))?;
        match key.as_ref() {
            "type" => record.record_type = parse_opt_str(value)?.unwrap_or_default(),
            "uuid" => record.uuid = parse_opt_str(value)?,
            "parentUuid" => record.parent_uuid = parse_opt_str(value)?,
            "timestamp" => {
                record.timestamp = parse_opt_str(value)?
                    .as_deref()
                    .and_then(parse_iso_timestamp)
            }
            "message" => {
                let part = scan_message(value)?;
                record.model = part.model;
                record.blocks = part.blocks;
            }
            _ => sc::skip_value(value)?,
        }
        Ok(record)
    })?;
    Ok(record)
}

fn scan_message(bytes: &mut Bytes) -> Result<MessagePart, sc::ScanError> {
    let mut part = MessagePart::default();
    sc::object(bytes, &mut part, |part, key, value| {
        let key = key
            .view::<str>()
            .map_err(|_| scan_syntax("invalid utf-8 key"))?;
        match key.as_ref() {
            "model" => part.model = parse_opt_str(value)?,
            "content" => part.blocks = scan_content(value)?,
            _ => sc::skip_value(value)?,
        }
        Ok(part)
    })?;
    Ok(part)
}

/// `message.content` is either a plain string (one text block) or an array of
/// content blocks.
fn scan_content(bytes: &mut Bytes) -> Result<Vec<RawBlock>, sc::ScanError> {
    let mut blocks: Vec<RawBlock> = Vec::new();
    match bytes.first().copied() {
        Some(b'"') => {
            let text = bytes_to_string(sc::parse_string(bytes)?)?;
            blocks.push(RawBlock {
                kind: BlockKind::Text,
                payload: text,
                correlator: None,
                signature: None,
                images: Vec::new(),
            });
        }
        Some(b'[') => {
            sc::array(bytes, &mut blocks, |blocks, element| {
                blocks.push(scan_content_block(element)?);
                Ok(blocks)
            })?;
        }
        _ => sc::skip_value(bytes)?,
    }
    Ok(blocks)
}

fn scan_content_block(bytes: &mut Bytes) -> Result<RawBlock, sc::ScanError> {
    let mut accum = BlockAccum::default();
    sc::object(bytes, &mut accum, |accum, key, value| {
        let key = key
            .view::<str>()
            .map_err(|_| scan_syntax("invalid utf-8 key"))?;
        match key.as_ref() {
            "type" => accum.btype = parse_opt_str(value)?.unwrap_or_default(),
            "text" => accum.text = parse_opt_str(value)?,
            "thinking" => accum.thinking = parse_opt_str(value)?,
            "signature" => accum.signature = parse_opt_str(value)?,
            "id" => accum.tool_id = parse_opt_str(value)?,
            "tool_use_id" => accum.tool_use_id = parse_opt_str(value)?,
            "input" => accum.input_raw = Some(capture_raw_json(value)?),
            "content" => {
                let (text, images) = scan_tool_result_content(value)?;
                accum.tool_result_content = Some(text);
                accum.tool_result_images = images;
            }
            "source" => accum.image_source = scan_opt_image_source(value)?,
            _ => sc::skip_value(value)?,
        }
        Ok(accum)
    })?;
    Ok(build_block(accum))
}

fn build_block(accum: BlockAccum) -> RawBlock {
    match accum.btype.as_str() {
        "text" => RawBlock {
            kind: BlockKind::Text,
            payload: accum.text.unwrap_or_default(),
            correlator: None,
            signature: None,
            images: Vec::new(),
        },
        "thinking" => RawBlock {
            kind: BlockKind::Thinking,
            payload: accum.thinking.unwrap_or_default(),
            correlator: None,
            signature: accum.signature,
            images: Vec::new(),
        },
        "tool_use" => RawBlock {
            kind: BlockKind::ToolUse,
            payload: accum.input_raw.unwrap_or_default(),
            correlator: accum.tool_id,
            signature: None,
            images: Vec::new(),
        },
        "tool_result" => RawBlock {
            kind: BlockKind::ToolResult,
            payload: accum.tool_result_content.unwrap_or_default(),
            correlator: accum.tool_use_id,
            signature: None,
            images: accum.tool_result_images,
        },
        "image" => RawBlock {
            kind: BlockKind::Image,
            payload: String::new(),
            correlator: None,
            signature: None,
            images: accum.image_source.into_iter().collect(),
        },
        _ => RawBlock {
            kind: BlockKind::Other,
            payload: String::new(),
            correlator: None,
            signature: None,
            images: Vec::new(),
        },
    }
}

/// A `tool_result` `content` field is a string, or an array of content blocks
/// (text and/or `image` blocks — screenshots), or (rarely) some other JSON —
/// captured raw as a fallback. Returns the joined text plus every embedded
/// image source, kept separate so images become their own content-facts.
fn scan_tool_result_content(
    bytes: &mut Bytes,
) -> Result<(String, Vec<RawImageSource>), sc::ScanError> {
    match bytes.first().copied() {
        Some(b'"') => Ok((bytes_to_string(sc::parse_string(bytes)?)?, Vec::new())),
        Some(b'[') => {
            let mut acc = (Vec::<String>::new(), Vec::<RawImageSource>::new());
            sc::array(bytes, &mut acc, |acc, element| {
                let part = scan_tool_result_part(element)?;
                if part.btype == "image" {
                    if let Some(source) = part.source {
                        acc.1.push(source);
                    }
                } else if let Some(text) = part.text {
                    if !text.is_empty() {
                        acc.0.push(text);
                    }
                }
                Ok(acc)
            })?;
            Ok((acc.0.join("\n\n"), acc.1))
        }
        _ => Ok((capture_raw_json(bytes)?, Vec::new())),
    }
}

/// One element of a tool_result content array, gathered order-independently.
#[derive(Default)]
struct ToolResultPart {
    btype: String,
    text: Option<String>,
    source: Option<RawImageSource>,
}

/// Scan one tool_result content element: a bare string, or a `{type,text}` /
/// `{type:"image",source:{…}}` block.
fn scan_tool_result_part(bytes: &mut Bytes) -> Result<ToolResultPart, sc::ScanError> {
    match bytes.first().copied() {
        Some(b'"') => Ok(ToolResultPart {
            text: Some(bytes_to_string(sc::parse_string(bytes)?)?),
            ..ToolResultPart::default()
        }),
        Some(b'{') => {
            let mut part = ToolResultPart::default();
            sc::object(bytes, &mut part, |part, key, value| {
                let key = key
                    .view::<str>()
                    .map_err(|_| scan_syntax("invalid utf-8 key"))?;
                match key.as_ref() {
                    "type" => part.btype = parse_opt_str(value)?.unwrap_or_default(),
                    "text" => part.text = parse_opt_str(value)?,
                    "source" => part.source = scan_opt_image_source(value)?,
                    _ => sc::skip_value(value)?,
                }
                Ok(part)
            })?;
            Ok(part)
        }
        _ => {
            sc::skip_value(bytes)?;
            Ok(ToolResultPart::default())
        }
    }
}

/// Scan an image `source` value when it is an object; skip anything else.
fn scan_opt_image_source(bytes: &mut Bytes) -> Result<Option<RawImageSource>, sc::ScanError> {
    if bytes.first().copied() != Some(b'{') {
        sc::skip_value(bytes)?;
        return Ok(None);
    }
    let mut source = RawImageSource::default();
    sc::object(bytes, &mut source, |source, key, value| {
        let key = key
            .view::<str>()
            .map_err(|_| scan_syntax("invalid utf-8 key"))?;
        match key.as_ref() {
            "type" => source.source_type = parse_opt_str(value)?.unwrap_or_default(),
            "media_type" => source.media_type = parse_opt_str(value)?,
            "data" => source.data = parse_opt_str(value)?,
            "url" => source.pointer = parse_opt_str(value)?,
            "file_id" => source.pointer = parse_opt_str(value)?,
            "file_size" | "size" => {
                source.size = capture_raw_json(value)?.trim().parse::<u64>().ok()
            }
            _ => sc::skip_value(value)?,
        }
        Ok(source)
    })?;
    Ok(Some(source))
}

fn collect_jsonl_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("read dir {}", path.display()))? {
        let entry = entry.context("read dir entry")?;
        let entry_path = entry.path();
        let file_type = entry.file_type().context("entry type")?;
        if file_type.is_dir() {
            // Recurse into subdirectories (projects/*/subagents/, etc).
            collect_jsonl_files(&entry_path, out)?;
        } else if file_type.is_file()
            && entry_path.extension().and_then(|ext| ext.to_str()) == Some("jsonl")
        {
            out.push(entry_path);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Timestamp parsing
// ---------------------------------------------------------------------------

/// Parse an ISO 8601 timestamp like "2026-03-01T15:34:01.542Z".
fn parse_iso_timestamp(value: &str) -> Option<Epoch> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    // hifitime's Epoch parser handles ISO 8601 / RFC 3339.
    trimmed.parse::<Epoch>().ok()
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn import_into_archive(
    path: &Path,
    pile_path: &Path,
    branch_name: &str,
    branch_id: Id,
) -> Result<()> {
    let _span = info_span!(
        "claude_code_import",
        path = %path.display(),
        branch = branch_name,
        branch_id = %format!("{branch_id:x}")
    )
    .entered();
    let import_start = Instant::now();
    let (mut repo, branch_id) = common::open_repo_for_write(pile_path, branch_id, branch_name)?;
    // Roster wiring (label → participant links on blocks) is the caller's
    // job; until then blocks keep only the raw source_author label.
    let res = import_claude_code_path(path, &mut repo, branch_id, None);
    tracing::info!(
        ok = res.is_ok(),
        elapsed_ms = import_start.elapsed().as_millis() as u64,
        "claude-code import finished"
    );
    let close_res = repo
        .close()
        .map_err(|e| anyhow!("close pile {}: {e:?}", pile_path.display()));
    match (res, close_res) {
        (Ok(stats), Ok(())) => {
            println!(
                "Imported {} file(s), {} block(s), {} content-fact(s) in {} new commit(s).",
                stats.files, stats.blocks, stats.content_facts, stats.commits
            );
            if !stats.wave_files.is_empty() {
                let per_wave = stats
                    .wave_files
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join("+");
                println!(
                    "Waves: {} ({} file(s) per wave), {} file(s) in the final pass.",
                    stats.wave_files.len(),
                    per_wave,
                    stats.final_pass_files,
                );
            }
            let r = stats.resolution;
            if r.cross_file_resolved > 0 {
                println!(
                    "Cross-file previous edge(s) resolved: {}.",
                    r.cross_file_resolved
                );
            }
            if r.total() > 0 {
                println!(
                    "Resolution gaps: {} dangling tool correlator(s), \
                     {} truly dangling parentUuid(s), \
                     {} parentUuid(s) into skipped lines (incl. cross-file), \
                     {} undecodable image(s), \
                     {} author/experiencer invariant breach(es).",
                    r.dangling_correlators,
                    r.cross_file_parents,
                    r.skipped_parents,
                    r.undecodable_images,
                    r.invariant_breaches,
                );
            }
            Ok(())
        }
        (Ok(_), Err(err)) => Err(err),
        (Err(err), Ok(())) => Err(err),
        (Err(err), Err(close_err)) => {
            eprintln!("warning: close pile after error: {close_err:#}");
            Err(err)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — projection only, no pile (in-memory fragment + query-back).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use triblespace::prelude::inlineencodings::Handle;

    /// A tiny synthetic `.claude` conversation: user → assistant (thinking +
    /// text + tool_use) → user (tool_result), plus a `system` line that must be
    /// ignored.
    const SAMPLE: &str = r#"{"type":"user","uuid":"u1","parentUuid":null,"timestamp":"2026-03-01T15:34:01.542Z","sessionId":"s1","message":{"role":"user","content":"hello there"}}
{"type":"assistant","uuid":"a1","parentUuid":"u1","timestamp":"2026-03-01T15:34:05.000Z","sessionId":"s1","message":{"role":"assistant","model":"claude-opus-4","content":[{"type":"thinking","thinking":"let me think","signature":"sig-abc"},{"type":"text","text":"hi!"},{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"ls"}}]}}
{"type":"user","uuid":"u2","parentUuid":"a1","timestamp":"2026-03-01T15:34:06.000Z","sessionId":"s1","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"file1\nfile2","is_error":false}]}}
{"type":"system","uuid":"sys1","parentUuid":"u2","timestamp":"2026-03-01T15:34:07.000Z","content":"ignored"}"#;

    fn project(sample: &str) -> Fragment {
        project_with(sample, None).fragment
    }

    fn project_with(sample: &str, roster: Option<&RosterIndex>) -> Projected {
        let bytes = Bytes::from_source(sample.as_bytes().to_vec());
        project_jsonl(&bytes, roster, None).expect("projection succeeds")
    }

    fn resolve_payload(frag: &Fragment, handle: Inline<Handle<LongString>>) -> String {
        let mut blobs = frag.blobs().clone();
        let reader = blobs.reader().expect("blob reader");
        let view: View<str> = reader
            .get::<View<str>, LongString>(handle)
            .expect("payload bytes present");
        view.as_ref().to_owned()
    }

    fn block_ids(frag: &Fragment) -> Vec<Id> {
        find!(
            (block: Id),
            pattern!(frag.facts(), [{ ?block @ common::metadata::tag: common::block::KIND }])
        )
        .map(|(block,)| block)
        .collect()
    }

    fn block_payloads(frag: &Fragment, block: Id) -> Vec<String> {
        find!(
            (cf: Id, payload: Inline<Handle<LongString>>),
            pattern!(frag.facts(), [
                { block @ common::block::contains: ?cf },
                { ?cf @ common::content_fact::payload: ?payload },
            ])
        )
        .map(|(_cf, payload)| resolve_payload(frag, payload))
        .collect()
    }

    fn block_directions(frag: &Fragment, block: Id) -> Vec<Id> {
        find!(
            (cf: Id, direction: Id),
            pattern!(frag.facts(), [
                { block @ common::block::contains: ?cf },
                { ?cf @ common::content_fact::direction: ?direction },
            ])
        )
        .map(|(_cf, direction)| direction)
        .collect()
    }

    fn previous_of(frag: &Fragment, block: Id) -> Option<Id> {
        find!(
            (prev: Id),
            pattern!(frag.facts(), [{ block @ common::block::previous: ?prev }])
        )
        .map(|(prev,)| prev)
        .next()
    }

    fn find_block(frag: &Fragment, needle: &str) -> Id {
        block_ids(frag)
            .into_iter()
            .find(|&block| block_payloads(frag, block).iter().any(|p| p.contains(needle)))
            .unwrap_or_else(|| panic!("no block contains payload {needle:?}"))
    }

    #[test]
    fn projects_one_block_per_user_or_assistant_record() {
        let frag = project(SAMPLE);
        // u1, a1, u2 → 3 blocks; the `system` line is ignored.
        assert_eq!(block_ids(&frag).len(), 3);
        // 1 (u1 text) + 3 (a1 thinking/text/tool_use) + 1 (u2 tool_result).
        let content_facts = find!(
            (cf: Id),
            pattern!(frag.facts(), [{ ?cf @ common::metadata::tag: common::content_fact::KIND }])
        )
        .count();
        assert_eq!(content_facts, 5);
    }

    #[test]
    fn previous_edges_chain_through_parent_uuid() {
        let frag = project(SAMPLE);
        let u1 = find_block(&frag, "hello there");
        let a1 = find_block(&frag, "hi!");
        let u2 = find_block(&frag, "file1");

        assert_eq!(previous_of(&frag, u1), None, "root record has no previous");
        assert_eq!(previous_of(&frag, a1), Some(u1));
        assert_eq!(previous_of(&frag, u2), Some(a1));
    }

    #[test]
    fn direction_follows_record_and_block_type() {
        let frag = project(SAMPLE);
        let u1 = find_block(&frag, "hello there");
        let a1 = find_block(&frag, "hi!");
        let u2 = find_block(&frag, "file1");

        let in_ = common::content_fact::direction::in_;
        let out_ = common::content_fact::direction::out_;

        assert!(block_directions(&frag, u1).iter().all(|&d| d == in_));
        assert!(block_directions(&frag, a1).iter().all(|&d| d == out_));
        assert!(block_directions(&frag, u2).iter().all(|&d| d == in_));
    }

    #[test]
    fn modality_and_payload_projected_per_content_block() {
        let frag = project(SAMPLE);
        let facts: Vec<(Id, Inline<Handle<LongString>>)> = find!(
            (modality: Id, payload: Inline<Handle<LongString>>),
            pattern!(frag.facts(), [{ _?cf @
                common::content_fact::modality: ?modality,
                common::content_fact::payload:  ?payload,
            }])
        )
        .collect();

        let payload_for = |wanted: Id| -> Option<String> {
            facts
                .iter()
                .find(|(modality, _)| *modality == wanted)
                .map(|(_, payload)| resolve_payload(&frag, *payload))
        };

        assert_eq!(
            payload_for(common::content_fact::modality::tool_call).as_deref(),
            Some(r#"{"command":"ls"}"#),
            "tool_use input rendered to raw-json text"
        );
        assert_eq!(
            payload_for(common::content_fact::modality::thinking).as_deref(),
            Some("let me think")
        );
        assert_eq!(
            payload_for(common::content_fact::modality::tool_result).as_deref(),
            Some("file1\nfile2")
        );

        let texts: HashSet<String> = facts
            .iter()
            .filter(|(modality, _)| *modality == common::content_fact::modality::text)
            .map(|(_, payload)| resolve_payload(&frag, *payload))
            .collect();
        assert!(texts.contains("hello there"));
        assert!(texts.contains("hi!"));
    }

    #[test]
    fn thinking_signature_is_non_identity_annotation() {
        let frag = project(SAMPLE);
        // The thinking content-fact carries its signature; find it and resolve.
        let signature = find!(
            (sig: Inline<Handle<LongString>>),
            pattern!(frag.facts(), [{ _?cf @
                common::content_fact::modality:  common::content_fact::modality::thinking,
                common::content_fact::signature: ?sig,
            }])
        )
        .map(|(sig,)| resolve_payload(&frag, sig))
        .next();
        assert_eq!(signature.as_deref(), Some("sig-abc"));
    }

    #[test]
    fn reprojection_is_content_addressed_stable() {
        let first: HashSet<Id> = block_ids(&project(SAMPLE)).into_iter().collect();
        let second: HashSet<Id> = block_ids(&project(SAMPLE)).into_iter().collect();
        assert_eq!(first, second, "re-projecting the same input yields identical block ids");
    }

    // ── phase 2: responds_to ────────────────────────────────────────────

    fn resolve_bytes(frag: &Fragment, handle: Inline<Handle<RawBytes>>) -> Vec<u8> {
        let mut blobs = frag.blobs().clone();
        let reader = blobs.reader().expect("blob reader");
        let bytes: Bytes = reader
            .get::<Bytes, RawBytes>(handle)
            .expect("blob bytes present");
        bytes.as_ref().to_vec()
    }

    /// Every `responds_to` edge in the fragment as (source cf, target cf).
    fn responds_to_edges(frag: &Fragment) -> Vec<(Id, Id)> {
        find!(
            (source: Id, target: Id),
            pattern!(frag.facts(), [{ ?source @ common::content_fact::responds_to: ?target }])
        )
        .collect()
    }

    #[test]
    fn tool_result_responds_to_tool_use_and_correlator_is_dropped() {
        let projected = project_with(SAMPLE, None);
        let frag = &projected.fragment;

        // The tool_result fact points at the tool_call fact — a semantic
        // `answers-that` edge, distinct from the blocks' `previous` chain.
        let edges: Vec<(Id, Id)> = find!(
            (result: Id, call: Id),
            pattern!(frag.facts(), [
                { ?result @
                    common::content_fact::modality: common::content_fact::modality::tool_result,
                    common::content_fact::responds_to: ?call,
                },
                { ?call @
                    common::content_fact::modality: common::content_fact::modality::tool_call,
                },
            ])
        )
        .collect();
        assert_eq!(edges.len(), 1, "exactly one tool_result → tool_call edge");
        assert_eq!(projected.stats.dangling_correlators, 0);

        // The vendor correlator string never persists: no text payload in the
        // fragment contains it (it lives in neither identity core nor pass 2).
        for (attr_payloads,) in find!(
            (payload: Inline<Handle<LongString>>),
            pattern!(frag.facts(), [{ _?cf @ common::content_fact::payload: ?payload }])
        ) {
            assert!(
                !resolve_payload(frag, attr_payloads).contains("toolu_1"),
                "correlator leaked into a content-fact payload"
            );
        }
        for (author,) in find!(
            (author: Inline<Handle<LongString>>),
            pattern!(frag.facts(), [{ _?b @ common::import_schema::source_author: ?author }])
        ) {
            assert!(!resolve_payload(frag, author).contains("toolu_1"));
        }
    }

    #[test]
    fn unresolved_correlator_is_counted_not_edged() {
        // The tool_result precedes its tool_use — violating the file-order
        // assumption the single forward pass relies on. The correlator must
        // be COUNTED as dangling (never silently orphaned) and no edge made;
        // this pins both the counter and the ordering assumption itself.
        let sample = r#"{"type":"user","uuid":"u1","parentUuid":null,"timestamp":"2026-03-01T15:34:01.542Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_x","content":"too early"}]}}
{"type":"assistant","uuid":"a1","parentUuid":"u1","timestamp":"2026-03-01T15:34:02.000Z","message":{"role":"assistant","model":"claude-opus-4","content":[{"type":"tool_use","id":"toolu_x","name":"Bash","input":{"command":"ls"}}]}}"#;
        let projected = project_with(sample, None);
        assert_eq!(projected.stats.dangling_correlators, 1);
        assert!(
            responds_to_edges(&projected.fragment).is_empty(),
            "a dangling correlator must not fabricate an edge"
        );
    }

    // ── phase 2: image content-facts ────────────────────────────────────

    const PNG_MAGIC: &[u8] = &[0x89, 0x50, 0x4E, 0x47];

    fn base64_image_sample() -> String {
        use base64::Engine as _;
        let data = base64::engine::general_purpose::STANDARD.encode(PNG_MAGIC);
        format!(
            r#"{{"type":"user","uuid":"u1","parentUuid":null,"timestamp":"2026-03-01T15:34:01.542Z","message":{{"role":"user","content":[{{"type":"text","text":"look at this"}},{{"type":"image","source":{{"type":"base64","media_type":"image/png","data":"{data}"}}}}]}}}}"#
        )
    }

    #[test]
    fn top_level_base64_image_becomes_blob_content_fact() {
        let projected = project_with(&base64_image_sample(), None);
        let frag = &projected.fragment;
        assert_eq!(projected.stats.undecodable_images, 0);

        let images: Vec<(Id, Id, Inline<Handle<RawBytes>>, String)> = find!(
            (cf: Id, direction: Id, blob: Inline<Handle<RawBytes>>, mime: String),
            pattern!(frag.facts(), [{ ?cf @
                common::content_fact::modality:  common::content_fact::modality::image,
                common::content_fact::direction: ?direction,
                common::content_fact::blob:      ?blob,
                common::content_fact::asset_mime: ?mime,
            }])
        )
        .collect();
        assert_eq!(images.len(), 1, "one image content-fact");
        let (cf, direction, blob, mime) = images[0].clone();
        assert_eq!(direction, common::content_fact::direction::in_);
        assert_eq!(mime, "image/png");
        assert_eq!(resolve_bytes(frag, blob), PNG_MAGIC);

        // The image fact sits beside the text fact on the SAME block.
        let block = find_block(frag, "look at this");
        let contains: HashSet<Id> = find!(
            (cf: Id),
            pattern!(frag.facts(), [{ block @ common::block::contains: ?cf }])
        )
        .map(|(cf,)| cf)
        .collect();
        assert_eq!(contains.len(), 2, "text fact + image fact");
        assert!(contains.contains(&cf));
    }

    #[test]
    fn tool_result_embedded_image_is_an_additional_fact_with_responds_to() {
        use base64::Engine as _;
        let data = base64::engine::general_purpose::STANDARD.encode(PNG_MAGIC);
        let sample = format!(
            r#"{{"type":"assistant","uuid":"a1","parentUuid":null,"timestamp":"2026-03-01T15:34:01.542Z","message":{{"role":"assistant","model":"claude-opus-4","content":[{{"type":"tool_use","id":"toolu_9","name":"Screenshot","input":{{"display":1}}}}]}}}}
{{"type":"user","uuid":"u1","parentUuid":"a1","timestamp":"2026-03-01T15:34:02.000Z","message":{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"toolu_9","content":[{{"type":"text","text":"screenshot below"}},{{"type":"image","source":{{"type":"base64","media_type":"image/png","data":"{data}"}}}}]}}]}}}}"#
        );
        let projected = project_with(&sample, None);
        let frag = &projected.fragment;
        assert_eq!(projected.stats.dangling_correlators, 0);

        // The tool_result block owns TWO content-facts: the text fact and the
        // image fact — the screenshot is not spliced into the text.
        let block = find_block(frag, "screenshot below");
        let contains: HashSet<Id> = find!(
            (cf: Id),
            pattern!(frag.facts(), [{ block @ common::block::contains: ?cf }])
        )
        .map(|(cf,)| cf)
        .collect();
        assert_eq!(contains.len(), 2, "tool_result text fact + image fact");

        // The image fact is direction `in`, carries the bytes, and — like the
        // text fact — answers the tool_call.
        let images: Vec<(Id, Inline<Handle<RawBytes>>)> = find!(
            (cf: Id, blob: Inline<Handle<RawBytes>>),
            pattern!(frag.facts(), [{ ?cf @
                common::content_fact::modality:  common::content_fact::modality::image,
                common::content_fact::direction: common::content_fact::direction::in_,
                common::content_fact::blob:      ?blob,
            }])
        )
        .collect();
        assert_eq!(images.len(), 1);
        let (image_cf, blob) = images[0];
        assert!(contains.contains(&image_cf));
        assert_eq!(resolve_bytes(frag, blob), PNG_MAGIC);

        let call_cf = find!(
            (cf: Id),
            pattern!(frag.facts(), [{ ?cf @
                common::content_fact::modality: common::content_fact::modality::tool_call,
            }])
        )
        .map(|(cf,)| cf)
        .next()
        .expect("tool_call fact present");
        let edges: HashSet<(Id, Id)> = responds_to_edges(frag).into_iter().collect();
        assert_eq!(edges.len(), 2, "text and image facts both answer the call");
        assert!(edges.iter().all(|&(_, target)| target == call_cf));
        assert!(edges.iter().any(|&(source, _)| source == image_cf));
    }

    #[test]
    fn non_base64_image_source_keeps_the_pointer() {
        let sample = r#"{"type":"user","uuid":"u1","parentUuid":null,"timestamp":"2026-03-01T15:34:01.542Z","message":{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://example.com/x.png","media_type":"image/png","file_size":123}}]}}"#;
        let projected = project_with(sample, None);
        let frag = &projected.fragment;
        assert_eq!(projected.stats.undecodable_images, 0);

        let pointers: Vec<(Id, Inline<Handle<LongString>>, String, Inline<U256BE>)> = find!(
            (cf: Id, pointer: Inline<Handle<LongString>>, mime: String, size: Inline<U256BE>),
            pattern!(frag.facts(), [{ ?cf @
                common::content_fact::modality:      common::content_fact::modality::image,
                common::content_fact::asset_pointer: ?pointer,
                common::content_fact::asset_mime:    ?mime,
                common::content_fact::asset_size:    ?size,
            }])
        )
        .collect();
        assert_eq!(pointers.len(), 1, "one pointer-identified image fact");
        let (cf, pointer, mime, size) = pointers[0].clone();
        assert_eq!(resolve_payload(frag, pointer), "https://example.com/x.png");
        assert_eq!(mime, "image/png");
        assert_eq!(size, 123u64.to_inline());

        // The keep-the-pointer branch holds no bytes: no `blob` on this fact.
        let blobs = find!(
            (blob: Inline<Handle<RawBytes>>),
            pattern!(frag.facts(), [{ cf @ common::content_fact::blob: ?blob }])
        )
        .count();
        assert_eq!(blobs, 0);
    }

    // ── phase 2: roster author/experiencer links ────────────────────────

    fn person(roster: &mut TribleSet, label: &str) -> Id {
        let id = ufoid().id;
        *roster += entity! { ExclusiveId::force_ref(&id) @
            common::metadata::tag: relations_schema::KIND_PERSON_ID,
            relations_schema::relations::label_norm: label,
        };
        id
    }

    fn author_of(frag: &Fragment, block: Id) -> Option<Id> {
        find!(
            (author: Id),
            pattern!(frag.facts(), [{ block @ common::block::author: ?author }])
        )
        .map(|(author,)| author)
        .next()
    }

    fn experiencer_of(frag: &Fragment, block: Id) -> Option<Id> {
        find!(
            (experiencer: Id),
            pattern!(frag.facts(), [{ block @ common::block::experiencer: ?experiencer }])
        )
        .map(|(experiencer,)| experiencer)
        .next()
    }

    #[test]
    fn roster_index_links_author_and_experiencer() {
        let mut roster = TribleSet::new();
        // The supervisor's wiring will map real labels; here "user" (the raw
        // source_author of user records) is JP, and the face is liora-cc.
        let jp = person(&mut roster, "user");
        let face = person(&mut roster, "liora-cc");
        let index = RosterIndex::build(&roster, Some("liora-cc"));

        let projected = project_with(SAMPLE, Some(&index));
        let frag = &projected.fragment;
        let u1 = find_block(frag, "hello there");
        let a1 = find_block(frag, "hi!");

        // In-block: the participant authored what the face experienced.
        assert_eq!(author_of(frag, u1), Some(jp));
        assert_eq!(experiencer_of(frag, u1), Some(face));
        // Out-block: the face authored its own production.
        assert_eq!(author_of(frag, a1), Some(face));
        assert_eq!(experiencer_of(frag, a1), Some(face));
        // direction=out ⟺ author==experiencer holds throughout.
        assert_eq!(projected.stats.invariant_breaches, 0);
    }

    #[test]
    fn roster_without_face_or_match_keeps_raw_label_only() {
        let mut roster = TribleSet::new();
        person(&mut roster, "someone-else");
        let index = RosterIndex::build(&roster, Some("not-in-roster"));

        let projected = project_with(SAMPLE, Some(&index));
        let frag = &projected.fragment;
        for block in block_ids(frag) {
            assert_eq!(author_of(frag, block), None);
            assert_eq!(experiencer_of(frag, block), None);
        }
        // Phase-1 behavior intact: the raw source_author label is still there
        // on every block (project the block too — u1 and u2 share the "user"
        // label handle, so labels alone would dedupe under set semantics).
        let labels = find!(
            (block: Id, label: Inline<Handle<LongString>>),
            pattern!(frag.facts(), [{ ?block @ common::import_schema::source_author: ?label }])
        )
        .count();
        assert_eq!(labels, 3);
    }

    #[test]
    fn author_experiencer_invariant_breach_is_counted() {
        let mut roster = TribleSet::new();
        // Degenerate roster: the face itself is labeled "user", so in-blocks
        // resolve author == experiencer — the invariant consistency check
        // must count (not abort on) the breach.
        person(&mut roster, "user");
        let index = RosterIndex::build(&roster, Some("user"));

        let projected = project_with(SAMPLE, Some(&index));
        // SAMPLE has two user records (u1, u2).
        assert_eq!(projected.stats.invariant_breaches, 2);
    }

    // ── phase 2: dangling parentUuid accounting ─────────────────────────

    #[test]
    fn dangling_parent_uuids_are_counted_by_class() {
        let sample = r#"{"type":"system","uuid":"sys1","parentUuid":null,"timestamp":"2026-03-01T15:34:00.000Z","content":"ignored"}
{"type":"user","uuid":"u1","parentUuid":"sys1","timestamp":"2026-03-01T15:34:01.000Z","message":{"role":"user","content":"parent was skipped"}}
{"type":"user","uuid":"u2","parentUuid":"ghost","timestamp":"2026-03-01T15:34:02.000Z","message":{"role":"user","content":"parent in another file"}}"#;
        let projected = project_with(sample, None);
        assert_eq!(projected.stats.skipped_parents, 1);
        assert_eq!(projected.stats.cross_file_parents, 1);

        // Neither block fabricates a `previous` edge.
        let frag = &projected.fragment;
        assert_eq!(previous_of(frag, find_block(frag, "parent was skipped")), None);
        assert_eq!(previous_of(frag, find_block(frag, "parent in another file")), None);
    }

    // ── phase 3: cross-file waves ───────────────────────────────────────

    /// In-memory mirror of [`import_directory_waves`] (no pile, no commit):
    /// pre-scan every sample, [`compute_waves`], project wave-by-wave against
    /// the growing snapshot — merging each wave's exports in sorted-name
    /// order with first-binding-wins, exactly the production merge — then
    /// project the never-eligible remainder as the final pass. Returns the
    /// per-name projections, the waves (as sorted name lists), and the
    /// final-pass names.
    fn project_waves(
        files: &[(&str, &str)],
    ) -> (HashMap<String, Projected>, Vec<Vec<String>>, Vec<String>) {
        let prescans: Vec<PreScan> = files
            .iter()
            .map(|(_, sample)| {
                prescan_jsonl(&Bytes::from_source(sample.as_bytes().to_vec()))
                    .expect("pre-scan succeeds")
            })
            .collect();
        let (waves, unresolvable) = compute_waves(&prescans);
        let final_pass = waves.len();
        let mut snapshot = UuidSnapshot::default();
        let mut projections: HashMap<String, Projected> = HashMap::new();
        let mut wave_names: Vec<Vec<String>> = Vec::new();
        let mut final_names: Vec<String> = Vec::new();
        for (pass, indices) in waves
            .iter()
            .chain(std::iter::once(&unresolvable))
            .enumerate()
        {
            let mut exports: Vec<(String, HashMap<String, Id>, HashSet<String>)> = Vec::new();
            for &i in indices {
                let (name, sample) = files[i];
                let projected = project_jsonl(
                    &Bytes::from_source(sample.as_bytes().to_vec()),
                    None,
                    Some(&snapshot),
                )
                .expect("projection succeeds");
                exports.push((
                    name.to_string(),
                    projected.uuid_to_block.clone(),
                    projected.skipped_uuids.clone(),
                ));
                projections.insert(name.to_string(), projected);
            }
            // Production merge: sorted name order, first binding wins.
            exports.sort_by(|a, b| a.0.cmp(&b.0));
            let mut names: Vec<String> = Vec::new();
            for (name, uuid_to_block, skipped_uuids) in exports {
                names.push(name);
                for (uuid, block) in uuid_to_block {
                    snapshot.blocks.entry(uuid).or_insert(block);
                }
                snapshot.skipped.extend(skipped_uuids);
            }
            if pass == final_pass {
                final_names = names;
            } else {
                wave_names.push(names);
            }
        }
        (projections, wave_names, final_names)
    }

    fn all_block_ids(projections: &HashMap<String, Projected>) -> HashSet<Id> {
        projections
            .values()
            .flat_map(|p| block_ids(&p.fragment))
            .collect()
    }

    const FILE_A: &str = r#"{"type":"user","uuid":"a-u1","parentUuid":null,"timestamp":"2026-03-01T15:34:01.542Z","message":{"role":"user","content":"root in file A"}}"#;
    const FILE_B: &str = r#"{"type":"user","uuid":"b-u1","parentUuid":"a-u1","timestamp":"2026-03-01T15:35:00.000Z","message":{"role":"user","content":"continues in file B"}}"#;

    #[test]
    fn cross_file_previous_resolves_through_wave_snapshot() {
        let (projections, waves, finals) = project_waves(&[("a", FILE_A), ("b", FILE_B)]);
        // A has no external refs → wave 1; B depends on A → wave 2.
        assert_eq!(
            waves,
            vec![vec!["a".to_string()], vec!["b".to_string()]],
            "dependency-ordered waves"
        );
        assert!(finals.is_empty(), "nothing unresolvable");

        let a = &projections["a"];
        let b = &projections["b"];
        let a_block = find_block(&a.fragment, "root in file A");
        let b_block = find_block(&b.fragment, "continues in file B");
        assert_eq!(
            previous_of(&b.fragment, b_block),
            Some(a_block),
            "B's root chains onto A's block across files"
        );
        assert_eq!(b.stats.cross_file_resolved, 1, "the resolved-edge counter");
        assert_eq!(b.stats.cross_file_parents, 0);
        assert_eq!(a.stats.cross_file_resolved, 0);
    }

    #[test]
    fn wave_projection_is_presentation_order_independent() {
        // DETERMINISM: the block-id set must not depend on the order the
        // files are presented in (production sorts paths, but the scheduler
        // itself must not care — the partition and the sorted-name merge are
        // both order-free).
        let forward = project_waves(&[("a", FILE_A), ("b", FILE_B)]);
        let reverse = project_waves(&[("b", FILE_B), ("a", FILE_A)]);
        assert_eq!(all_block_ids(&forward.0), all_block_ids(&reverse.0));
        assert_eq!(forward.1, reverse.1, "identical wave partition");
    }

    #[test]
    fn mutual_cycle_lands_in_final_pass_counted_dangling() {
        let a = r#"{"type":"user","uuid":"a-u1","parentUuid":"b-u1","timestamp":"2026-03-01T15:34:01.000Z","message":{"role":"user","content":"cycle half a"}}"#;
        let b = r#"{"type":"user","uuid":"b-u1","parentUuid":"a-u1","timestamp":"2026-03-01T15:34:02.000Z","message":{"role":"user","content":"cycle half b"}}"#;
        let (projections, waves, finals) = project_waves(&[("a", a), ("b", b)]);
        // Neither file is ever eligible — no deadlock, both in the final pass.
        assert!(waves.is_empty(), "a cycle produces no eligible wave");
        assert_eq!(finals, vec!["a".to_string(), "b".to_string()]);
        for (name, projected) in &projections {
            assert_eq!(
                projected.stats.cross_file_parents, 1,
                "{name}: cycle ref counted truly dangling"
            );
            assert_eq!(projected.stats.cross_file_resolved, 0);
            assert_eq!(projected.stats.skipped_parents, 0);
            for block in block_ids(&projected.fragment) {
                assert_eq!(
                    previous_of(&projected.fragment, block),
                    None,
                    "{name}: no fabricated previous edge"
                );
            }
        }
    }

    #[test]
    fn cross_file_ref_to_skipped_line_counts_as_skipped() {
        // File A holds ONLY a system line (projects no block — its fragment
        // is empty, but its skipped uuid still merges into the snapshot).
        let a = r#"{"type":"system","uuid":"a-sys1","parentUuid":null,"timestamp":"2026-03-01T15:34:00.000Z","content":"ignored"}"#;
        let b = r#"{"type":"user","uuid":"b-u1","parentUuid":"a-sys1","timestamp":"2026-03-01T15:34:01.000Z","message":{"role":"user","content":"child of a skipped line"}}"#;
        let (projections, waves, finals) = project_waves(&[("a", a), ("b", b)]);
        // The DEFINING file is known from the pre-scan, so B waits for A and
        // classifies against the snapshot — never the final pass.
        assert_eq!(waves, vec![vec!["a".to_string()], vec!["b".to_string()]]);
        assert!(finals.is_empty());

        let b = &projections["b"];
        assert_eq!(b.stats.skipped_parents, 1, "cross-file-skipped, not dangling");
        assert_eq!(b.stats.cross_file_parents, 0);
        assert_eq!(b.stats.cross_file_resolved, 0);
        assert_eq!(
            previous_of(&b.fragment, find_block(&b.fragment, "child of a skipped line")),
            None,
            "a skipped parent projects no block, so no edge"
        );
    }
}
