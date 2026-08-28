//! One-time transition from Memory's revision DAG to an episodic journal.
//!
//! The old named `memory` collection is monotone: it contains every canonical
//! chunk ever written, plus revision edges and retraction entities.  The new
//! `memory-journal` collection deliberately gives those records a different
//! interpretation. Every selected canonical chunk coexists; historical
//! `metadata::supersedes` facts survive only as identity material, and no
//! retraction entity is copied.
//!
//! Which mechanically broken chunks to omit is autobiographical data, not
//! public program logic.  Activation therefore consumes a private,
//! source-bound manifest instead of baking Memory ids into this crate.  The
//! manifest names the exact legacy fact-set fingerprint and every chunk to
//! omit. A changed source, a missing omission, or a kept hard reference into
//! an omission fails before publication.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use triblespace::core::blob::encodings::UnknownBlob;
use triblespace::core::blob::Blob;
use triblespace::core::collection::reach;
use triblespace::core::collection::records::CollectionName;
use triblespace::core::collection::{Collection, CollectionAdmission, CollectionCommit};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::*;

use faculties::memory::{self, ChunkContent, ChunkRow, MemoryCatalog};
use faculties::schemas::memory::{ctx, DEFAULT_SCOPE_ID};
use faculties::storage::{load_signer, open_pile_strict, publish_fragment};

const MANIFEST_HEADER: &str = "memory-journal-omit-v1";
const LEGACY_COLLECTION_NAME: &str = "memory";
const SOURCE_DIGEST_CONTEXT: &str = "faculties memory journal legacy facts v1";

/// Stable description of the exact legacy source observed by a dry run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceReport {
    pub facts: usize,
    pub commits: usize,
    pub chunks: usize,
    pub digest: [u8; 32],
}

impl SourceReport {
    pub fn digest_hex(self) -> String {
        hex::encode(self.digest)
    }
}

/// Parsed private omission manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OmissionManifest {
    source_facts: usize,
    source_chunks: usize,
    source_digest: [u8; 32],
    omitted: BTreeSet<Id>,
}

impl OmissionManifest {
    pub fn source_facts(&self) -> usize {
        self.source_facts
    }

    pub fn source_chunks(&self) -> usize {
        self.source_chunks
    }

    pub fn source_digest(&self) -> [u8; 32] {
        self.source_digest
    }

    pub fn omitted(&self) -> &BTreeSet<Id> {
        &self.omitted
    }

    /// Parse a deliberately tiny line format; comments and blank lines are
    /// ignored, while every semantic field is exact and single-valued.
    pub fn parse(text: &str) -> Result<Self> {
        let mut lines = text.lines().enumerate().filter_map(|(index, line)| {
            let line = line.trim();
            (!line.is_empty() && !line.starts_with('#')).then_some((index + 1, line))
        });
        let Some((header_line, header)) = lines.next() else {
            bail!("Memory journal omission manifest is empty");
        };
        if header != MANIFEST_HEADER {
            bail!(
                "Memory journal omission manifest line {header_line} is {header:?}; expected {MANIFEST_HEADER:?}"
            );
        }

        let mut source_facts = None;
        let mut source_chunks = None;
        let mut source_digest = None;
        let mut omitted = BTreeSet::new();
        for (line_number, line) in lines {
            let Some((field, value)) = line.split_once(char::is_whitespace) else {
                bail!("manifest line {line_number} has no value: {line:?}");
            };
            let value = value.trim();
            match field {
                "source-facts" => set_once(
                    &mut source_facts,
                    value
                        .parse::<usize>()
                        .with_context(|| format!("parse source-facts on line {line_number}"))?,
                    "source-facts",
                    line_number,
                )?,
                "source-chunks" => set_once(
                    &mut source_chunks,
                    value
                        .parse::<usize>()
                        .with_context(|| format!("parse source-chunks on line {line_number}"))?,
                    "source-chunks",
                    line_number,
                )?,
                "source-digest" => {
                    let raw = hex::decode(value)
                        .with_context(|| format!("parse source-digest on line {line_number}"))?;
                    let digest: [u8; 32] = raw.try_into().map_err(|bytes: Vec<u8>| {
                        anyhow!(
                            "source-digest on line {line_number} is {} bytes; expected 32",
                            bytes.len()
                        )
                    })?;
                    set_once(&mut source_digest, digest, "source-digest", line_number)?;
                }
                "omit" => {
                    let id = Id::from_hex(value).ok_or_else(|| {
                        anyhow!("omit id on line {line_number} is not 32 hexadecimal digits")
                    })?;
                    if !omitted.insert(id) {
                        bail!("omit id {id:X} is repeated on line {line_number}");
                    }
                }
                other => bail!("unknown manifest field {other:?} on line {line_number}"),
            }
        }

        Ok(Self {
            source_facts: source_facts
                .ok_or_else(|| anyhow!("manifest is missing source-facts"))?,
            source_chunks: source_chunks
                .ok_or_else(|| anyhow!("manifest is missing source-chunks"))?,
            source_digest: source_digest
                .ok_or_else(|| anyhow!("manifest is missing source-digest"))?,
            omitted,
        })
    }

    pub fn read(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("read Memory journal manifest {}", path.display()))?;
        Self::parse(&text)
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, field: &str, line: usize) -> Result<()> {
    if slot.replace(value).is_some() {
        bail!("manifest field {field} is repeated on line {line}");
    }
    Ok(())
}

/// Complete dry-run result and deterministic target fragment.
#[derive(Clone, Debug)]
pub struct JournalPlan {
    pub source: SourceReport,
    pub omitted_chunks: usize,
    pub selected_chunks: usize,
    pub selected_facts: usize,
    pub target_chunks_before: usize,
    pub already_complete: bool,
    fragment: Fragment,
}

/// Idempotent activation outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationOutcome {
    Published(CollectionCommit),
    AlreadyComplete,
}

fn legacy_collection(storage: Pile, signer: SigningKey) -> Collection<Pile> {
    let name = CollectionName::new(LEGACY_COLLECTION_NAME)
        .expect("the historical Memory collection name is legal");
    Collection::new(
        storage,
        &name,
        signer.verifying_key(),
        signer,
        reach::private(),
        CollectionAdmission::open(),
    )
}

fn source_digest(facts: &TribleSet) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SOURCE_DIGEST_CONTEXT);
    hasher.update(&(facts.len() as u64).to_le_bytes());
    // `TribleSet::iter()` follows the physical PATCH cover and is deliberately
    // representation-dependent. A migration guard must survive equivalent
    // merge/compaction histories, so hash canonical byte order explicitly.
    for fact in facts.iter_ordered() {
        hasher.update(&fact.data);
    }
    *hasher.finalize().as_bytes()
}

fn source_report(facts: &TribleSet, commits: usize, catalog: &MemoryCatalog) -> SourceReport {
    SourceReport {
        facts: facts.len() as usize,
        commits,
        chunks: catalog.chunks.len(),
        digest: source_digest(facts),
    }
}

fn open_snapshots(
    pile_path: &Path,
    key_path: Option<&Path>,
) -> Result<(
    SigningKey,
    triblespace::core::collection::CollectionSnapshot<PileReader>,
    triblespace::core::collection::CollectionSnapshot<PileReader>,
)> {
    let signer = load_signer(pile_path, key_path)
        .context("load durable signer for Memory journal migration")?;
    let pile = open_pile_strict(pile_path)?;

    let mut source = legacy_collection(pile, signer.clone());
    let source_snapshot = source
        .snapshot()
        .context("snapshot retired Memory revision-DAG collection")?;
    let pile = source.into_storage();

    let mut target = faculties::collection_names::open(pile, DEFAULT_SCOPE_ID, signer.clone());
    let target_snapshot = target
        .snapshot()
        .context("snapshot episodic Memory journal collection")?;
    let pile = target.into_storage();
    pile.close().context("close Memory migration pile")?;
    Ok((signer, source_snapshot, target_snapshot))
}

/// Inspect the immutable legacy source without selecting or publishing rows.
pub fn inspect_path(pile_path: &Path, key_path: Option<&Path>) -> Result<SourceReport> {
    let (_, source, _) = open_snapshots(pile_path, key_path)?;
    let catalog = memory::validate_catalog(source.reader(), source.facts())
        .context("validate retired Memory catalog")?;
    Ok(source_report(
        source.facts(),
        source.commits().len(),
        &catalog,
    ))
}

fn validate_manifest(source: SourceReport, manifest: &OmissionManifest) -> Result<()> {
    if manifest.source_facts != source.facts {
        bail!(
            "Memory journal manifest names {} source facts, but the frozen source has {}",
            manifest.source_facts,
            source.facts
        );
    }
    if manifest.source_chunks != source.chunks {
        bail!(
            "Memory journal manifest names {} canonical chunks, but the frozen source has {}",
            manifest.source_chunks,
            source.chunks
        );
    }
    if manifest.source_digest != source.digest {
        bail!(
            "Memory journal manifest source digest {} does not match frozen source {}",
            hex::encode(manifest.source_digest),
            source.digest_hex()
        );
    }
    Ok(())
}

fn rebuilt_chunk(row: &ChunkRow, reader: &PileReader) -> Result<Fragment> {
    let summary = match row.content {
        ChunkContent::Text(handle) => Some(handle),
        ChunkContent::Image(_) => None,
    };
    let image = match row.content {
        ChunkContent::Text(_) => None,
        ChunkContent::Image(handle) => Some(handle),
    };
    let mut fragment = entity! {
        metadata::tag: &faculties::schemas::memory::KIND_CHUNK_ID,
        ctx::summary?: summary.as_ref(),
        ctx::image?: image.as_ref(),
        ctx::start_at: row.start_at,
        ctx::end_at: row.end_at,
        ctx::lens?: row.lens.as_ref(),
        ctx::reference*: row.references.iter(),
        ctx::about_exec_result?: row.about_exec_result.as_ref(),
        ctx::about_archive_message?: row.about_archive_message.as_ref(),
        metadata::supersedes*: row.predecessors.iter(),
    };
    let rebuilt = fragment
        .root()
        .expect("canonical Memory chunk has one intrinsic root");
    if rebuilt != row.id {
        bail!(
            "rebuilding historical Memory chunk {:X} produced {:X}",
            row.id,
            rebuilt
        );
    }
    for at in &row.observed_at {
        fragment += entity! { ExclusiveId::force_ref(&row.id) @ metadata::created_at: at };
    }
    for alias in &row.aliases {
        let alias = inlineencodings::GenId::inline_from(*alias);
        fragment += entity! { ExclusiveId::force_ref(&row.id) @ metadata::anchor: alias };
    }

    let mut handles = BTreeSet::new();
    match row.content {
        ChunkContent::Text(handle) => {
            handles.insert(handle.transmute());
        }
        ChunkContent::Image(handle) => {
            handles.insert(handle.transmute());
        }
    }
    if let Some(handle) = row.lens {
        handles.insert(handle.transmute());
    }
    for handle in handles {
        let blob: Blob<UnknownBlob> = reader
            .get(handle)
            .with_context(|| format!("read payload for Memory chunk {:X}", row.id))?;
        let stored = fragment.blobs_mut().insert(blob);
        if stored != handle {
            bail!(
                "payload bytes for Memory chunk {:X} do not hash to their recorded handle",
                row.id
            );
        }
    }
    Ok(fragment)
}

/// Build and validate the exact new journal epoch without writing.
pub fn plan_path(
    pile_path: &Path,
    key_path: Option<&Path>,
    manifest_path: &Path,
) -> Result<JournalPlan> {
    let manifest = OmissionManifest::read(manifest_path)?;
    let (_, source_snapshot, target_snapshot) = open_snapshots(pile_path, key_path)?;
    let source_catalog =
        memory::validate_catalog(source_snapshot.reader(), source_snapshot.facts())
            .context("validate retired Memory catalog")?;
    let source = source_report(
        source_snapshot.facts(),
        source_snapshot.commits().len(),
        &source_catalog,
    );
    validate_manifest(source, &manifest)?;

    for omitted in &manifest.omitted {
        if !source_catalog.chunks.contains_key(omitted) {
            bail!("manifest omits unknown canonical Memory chunk {omitted:X}");
        }
    }

    for row in source_catalog.chunks.values() {
        if manifest.omitted.contains(&row.id) {
            continue;
        }
        for reference in &row.references {
            if manifest.omitted.contains(reference) {
                bail!(
                    "kept Memory chunk {:X} hard-references omitted chunk {reference:X}",
                    row.id
                );
            }
        }
        for predecessor in &row.predecessors {
            if manifest.omitted.contains(predecessor) {
                bail!(
                    "kept Memory chunk {:X} retains historical identity edge to omitted chunk {predecessor:X}",
                    row.id
                );
            }
        }
    }

    let target_catalog =
        memory::validate_catalog(target_snapshot.reader(), target_snapshot.facts())
            .context("validate existing episodic Memory journal")?;
    for omitted in &manifest.omitted {
        if target_catalog.chunks.contains_key(omitted) {
            bail!(
                "episodic Memory target already contains omitted chunk {omitted:X}; append-only activation cannot remove it"
            );
        }
    }

    let selected: BTreeSet<_> = source_catalog
        .chunks
        .keys()
        .copied()
        .filter(|id| !manifest.omitted.contains(id))
        .collect();
    let already_complete = selected
        .iter()
        .all(|id| target_catalog.chunks.contains_key(id));

    let mut fragment = Fragment::empty();
    for id in &selected {
        fragment += rebuilt_chunk(&source_catalog.chunks[id], source_snapshot.reader())?;
    }
    let candidate =
        memory::validate_candidate(target_snapshot.reader(), target_snapshot.facts(), &fragment)
            .context("validate complete episodic Memory candidate")?;
    for id in &selected {
        if !candidate.chunks.contains_key(id) {
            bail!("candidate lost selected Memory chunk {id:X}");
        }
    }
    for id in &manifest.omitted {
        if candidate.chunks.contains_key(id) {
            bail!("candidate unexpectedly contains omitted Memory chunk {id:X}");
        }
    }

    Ok(JournalPlan {
        source,
        omitted_chunks: manifest.omitted.len(),
        selected_chunks: selected.len(),
        selected_facts: fragment.facts().len() as usize,
        target_chunks_before: target_catalog.chunks.len(),
        already_complete,
        fragment,
    })
}

/// Publish the exact candidate once; replay observes that the selected set is
/// already present and appends nothing.
pub fn activate(
    pile_path: &Path,
    key_path: Option<&Path>,
    manifest_path: &Path,
) -> Result<(JournalPlan, ActivationOutcome)> {
    let plan = plan_path(pile_path, key_path, manifest_path)?;
    if plan.already_complete {
        return Ok((plan, ActivationOutcome::AlreadyComplete));
    }
    let commit = publish_fragment(pile_path, key_path, DEFAULT_SCOPE_ID, plan.fragment.clone())
        .context("publish episodic Memory journal seed")?;

    let verified = plan_path(pile_path, key_path, manifest_path)
        .context("verify episodic Memory journal after publication")?;
    if !verified.already_complete {
        bail!("Memory journal publication completed without its full selected set");
    }
    Ok((verified, ActivationOutcome::Published(commit)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    use faculties::clock;
    use faculties::memory::{ChunkDraft, ChunkDraftContent};
    use faculties::storage::initialize_signer;
    use hifitime::Epoch;

    fn point(seconds: f64) -> faculties::memory::IntervalValue {
        let at = Epoch::from_tai_seconds(seconds);
        (at, at).try_to_inline().unwrap()
    }

    fn chunk(summary: &str, at: f64) -> (Fragment, Id) {
        memory::chunk_fragment(ChunkDraft {
            content: ChunkDraftContent::Text(summary.to_owned()),
            start_at: point(at),
            end_at: point(at + 1.0),
            lens: None,
            references: BTreeSet::new(),
            about_exec_result: None,
            about_archive_message: None,
            observed_at: BTreeSet::from([clock::point(Epoch::from_tai_seconds(at + 2.0)).unwrap()]),
            aliases: BTreeSet::new(),
        })
        .unwrap()
    }

    fn write_manifest(path: &Path, source: SourceReport, omitted: &[Id]) {
        let mut text = format!(
            "{MANIFEST_HEADER}\nsource-facts {}\nsource-chunks {}\nsource-digest {}\n",
            source.facts,
            source.chunks,
            source.digest_hex()
        );
        for id in omitted {
            text.push_str(&format!("omit {id:X}\n"));
        }
        fs::write(path, text).unwrap();
    }

    #[test]
    fn manifest_is_strict_and_source_bound() {
        let id = Id::new([0x42; 16]).unwrap();
        let text = format!(
            "{MANIFEST_HEADER}\nsource-facts 3\nsource-chunks 2\nsource-digest {}\nomit {id:X}\n",
            hex::encode([0x55; 32])
        );
        let parsed = OmissionManifest::parse(&text).unwrap();
        assert_eq!(parsed.source_facts(), 3);
        assert_eq!(parsed.source_chunks(), 2);
        assert_eq!(parsed.source_digest(), [0x55; 32]);
        assert_eq!(parsed.omitted(), &BTreeSet::from([id]));
        assert!(OmissionManifest::parse(&format!("{text}omit {id:X}\n")).is_err());
    }

    #[test]
    fn source_digest_ignores_patch_construction_history() {
        let left = entity! { _ @ metadata::tag: &Id::new([0x31; 16]).unwrap() };
        let right = entity! { _ @ metadata::tag: &Id::new([0x32; 16]).unwrap() };
        let mut one = left.facts().clone();
        one += right.facts().clone();
        let mut other = right.into_facts();
        other += left.into_facts();
        assert_eq!(one, other);
        assert_eq!(source_digest(&one), source_digest(&other));
    }

    #[test]
    fn activation_selects_exact_chunks_and_replay_appends_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("self.pile");
        let key_path = directory.path().join("self.key");
        let manifest_path = directory.path().join("memory.omit");
        File::create(&pile_path).unwrap();
        let signer = initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let pile = open_pile_strict(&pile_path).unwrap();
        let mut legacy = legacy_collection(pile, signer);
        let (keep, keep_id) = chunk("keep", 10.0);
        let (omit, omit_id) = chunk("omit", 20.0);
        let mut source = keep;
        source += omit;
        legacy.commit(source).unwrap();
        legacy.into_storage().close().unwrap();

        let inspected = inspect_path(&pile_path, Some(&key_path)).unwrap();
        assert_eq!(inspected.chunks, 2);
        write_manifest(&manifest_path, inspected, &[omit_id]);

        let planned = plan_path(&pile_path, Some(&key_path), &manifest_path).unwrap();
        assert_eq!(planned.selected_chunks, 1);
        assert_eq!(planned.omitted_chunks, 1);
        assert!(!planned.already_complete);

        let (_, first) = activate(&pile_path, Some(&key_path), &manifest_path).unwrap();
        assert!(matches!(first, ActivationOutcome::Published(_)));
        let (again, second) = activate(&pile_path, Some(&key_path), &manifest_path).unwrap();
        assert_eq!(second, ActivationOutcome::AlreadyComplete);
        assert!(again.already_complete);

        let pile = open_pile_strict(&pile_path).unwrap();
        let signer = load_signer(&pile_path, Some(&key_path)).unwrap();
        let mut target = faculties::collection_names::open(pile, DEFAULT_SCOPE_ID, signer);
        let snapshot = target.snapshot().unwrap();
        let catalog = memory::validate_catalog(snapshot.reader(), snapshot.facts()).unwrap();
        assert!(catalog.chunks.contains_key(&keep_id));
        assert!(!catalog.chunks.contains_key(&omit_id));
        target.into_storage().close().unwrap();
    }
}
