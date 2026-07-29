//! Rebuild legacy file lineages around canonical media-type entities.
//!
//! Replacing the old inline `file::mime: ShortString` fact changes every file
//! id. Because Files is a Merkle graph, directory, import, and PDF-page ids can
//! change transitively as well; Mail and archive-style faculties then need
//! their references rewritten against the same complete id map, while Wiki
//! needs new append-only heads because its literal links participate in
//! version identity. This module provides those pure semantic passes and
//! leaves branch pinning, commits, receipts, validation gates, and cutover to
//! the `migrations` faculty.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;
use triblespace::core::inline::encodings::time::Lower;
use triblespace::core::metadata;
use triblespace::core::repo::{BlobStore, Workspace};
#[cfg(test)]
use triblespace::core::trible::{A_END, A_START};
use triblespace::core::trible::{E_END, E_START, V_END, V_START};
use triblespace::prelude::blobencodings::{LongString, RawBytes};
use triblespace::prelude::inlineencodings::{GenId, Handle, NsTAIInterval};
use triblespace::prelude::*;

use crate::files as file_capability;
use crate::schemas::archive::archive;
use crate::schemas::files::{
    file, page, KIND_DIRECTORY, KIND_FILE, KIND_IMPORT, KIND_MEDIA_TYPE, KIND_PAGE,
};
use crate::schemas::mail::mail;
use crate::schemas::wiki::attrs as wiki;

/// Stable identity of this migration, minted with `trible genid` on 2026-07-29.
pub const MIGRATION_ID: Id = id_hex!("E4DB50994833CFFB8B0566260D564A85");
pub const MIGRATION_NAME: &str = "canonical-file-media-types";
pub const MIGRATION_DESCRIPTION: &str =
    "rebuild Files and referring faculty lineages around lossless media-type entities";

/// The removed schema is intentionally private to the migration.
mod legacy {
    use triblespace::prelude::*;

    attributes! {
        "BFE2C88ECD13D56F80967C343FC072EE" as mime: inlineencodings::ShortString;
        "EA8B5429A86AF26D2B87F169AFEE3919" as imported_at: inlineencodings::NsTAIInterval;
    }
}

type NameHandle = Inline<Handle<LongString>>;
/// Explicit current-encoding timestamp supplied by the migration runner.
pub type MigrationTimestamp = Inline<NsTAIInterval>;
type Timestamp = MigrationTimestamp;

/// Why a legacy inline MIME value became the selected canonical media type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaTypeSource {
    /// The legacy value parsed cleanly and was not detectably truncated.
    LegacyValue,
    /// The legacy value was invalid or looked truncated; the filename supplied
    /// a known, lossless media type.
    FilenameRecovery,
    /// Neither the legacy value nor filename yielded a usable type.
    GenericDefault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyFileIdentity {
    Intrinsic,
    /// Historical source-local id forced by Mail, Teams, or Discord.
    ForcedSourceId,
}

/// An auditable choice made while recovering one legacy file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaTypeDecision {
    pub old_file: Id,
    pub legacy_value: String,
    pub selected: String,
    pub source: MediaTypeSource,
    pub old_identity: LegacyFileIdentity,
}

/// Counts for the rebuilt Files snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FilesRewriteReport {
    pub input_tribles: usize,
    pub output_tribles: usize,
    pub legacy_files: usize,
    /// Legacy records whose ids match the historical intrinsic constructor.
    pub intrinsic_legacy_files: usize,
    /// Legacy Mail/Teams/Discord records whose producer deliberately forced a
    /// source-local id instead of using the file core's derived id.
    pub forced_legacy_files: usize,
    pub canonical_files: usize,
    pub distinct_output_files: usize,
    pub directories: usize,
    pub imports: usize,
    pub legacy_import_timestamps: usize,
    pub pages: usize,
    pub filename_recoveries: usize,
    pub generic_defaults: usize,
    pub remapped_subject_facts: usize,
    pub remapped_reference_facts: usize,
}

/// A complete semantic rewrite of the Files branch.
#[derive(Clone, Debug)]
pub struct FilesRewrite {
    /// Replacement branch facts. This is a full snapshot, not an additive
    /// delta; mixing it into the legacy branch would retain both lineages. The
    /// fragment also carries every newly introduced media-type/name blob, so a
    /// dry run needs no writes and apply can commit it directly.
    pub content: Fragment,
    /// Complete map for every file, directory, import, and page entity.
    pub ids: BTreeMap<Id, Id>,
    /// Old ids that specifically denoted file artifacts. The complete map also
    /// contains directories, imports, and pages; reference-branch occurrence
    /// repair must only synthesize artifact links for this subset.
    pub file_ids: BTreeSet<Id>,
    pub decisions: Vec<MediaTypeDecision>,
    pub report: FilesRewriteReport,
}

impl FilesRewrite {
    pub fn facts(&self) -> &TribleSet {
        self.content.facts()
    }
}

/// Counts for one branch whose references were rewritten.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReferenceRewriteReport {
    pub input_tribles: usize,
    pub output_tribles: usize,
    pub remapped_subject_facts: usize,
    pub remapped_reference_facts: usize,
    /// Legacy archive occurrence ids that gained an explicit
    /// `archive::attachment_file` edge.
    pub occurrence_file_links_added: usize,
}

/// A full replacement snapshot for a branch referring to Files entities.
#[derive(Clone, Debug)]
pub struct ReferenceRewrite {
    pub facts: TribleSet,
    pub report: ReferenceRewriteReport,
}

/// Counts for the Wiki-specific half of the migration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WikiRewriteReport {
    pub input_tribles: usize,
    pub additions_tribles: usize,
    pub fragments: usize,
    pub edited_fragments: usize,
    /// Sum of distinct remapped Files targets within each edited version.
    pub remapped_file_targets: usize,
    pub remapped_file_literals: usize,
}

/// Append-only edits for the current heads of the Wiki branch.
///
/// Wiki needs a dedicated transform because the literal `files:<id>` is part
/// of `wiki::content`, hence part of a version's intrinsic identity. Merely
/// rewriting the derived `wiki::references_file` edge would make the index
/// disagree with what the viewer opens. Historical versions remain immutable;
/// exact links to them are stable citations.
#[derive(Clone, Debug)]
pub struct WikiRewrite {
    /// Directly committable additions, including every new content blob.
    pub additions: Fragment,
    /// Previous latest version -> migrated latest version. This is audit data,
    /// never a global replacement map: old versions intentionally survive.
    pub edits: BTreeMap<Id, Id>,
    pub report: WikiRewriteReport,
}

impl WikiRewrite {
    pub fn facts(&self) -> &TribleSet {
        self.additions.facts()
    }
}

#[derive(Clone, Debug)]
struct DirectoryRecord {
    name: NameHandle,
    children: BTreeSet<Id>,
}

#[derive(Clone, Debug)]
struct ImportRecord {
    root: Id,
    imported_at: Timestamp,
    source_path: NameHandle,
}

#[derive(Clone, Debug)]
struct PageRecord {
    parent: Id,
    index: String,
}

/// GenId-valued attributes whose targets may be Files entities.
///
/// Values under other attributes are never interpreted by byte shape alone:
/// they may be hashes or handles that merely resemble a GenId. Callers with a
/// project-specific GenId edge register it explicitly through
/// [`rewrite_reference_branch_with`].
pub fn reference_attributes() -> BTreeSet<Id> {
    [
        file::children.id(),
        file::root.id(),
        page::parent.id(),
        mail::attachment.id(),
        archive::attachment_file.id(),
    ]
    .into_iter()
    .collect()
}

fn artifact_reference_attributes() -> BTreeSet<Id> {
    [mail::attachment.id(), archive::attachment_file.id()]
        .into_iter()
        .collect()
}

fn exactly_one<T>(values: Vec<T>, entity: Id, field: &str) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "entity {entity:x} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(values.into_iter().next().expect("length checked"))
}

fn optional_singleton<T>(values: Vec<T>, entity: Id, field: &str) -> Result<Option<T>> {
    if values.len() > 1 {
        bail!(
            "entity {entity:x} has {} values for {field}; expected at most one",
            values.len()
        );
    }
    Ok(values.into_iter().next())
}

fn read_name<Blobs: BlobStore>(
    workspace: &mut Workspace<Blobs>,
    handle: NameHandle,
) -> Result<String> {
    let view = workspace
        .get::<View<str>, LongString>(handle)
        .map_err(|err| anyhow!("read LongString blob: {err:?}"))?;
    Ok(view.as_ref().to_owned())
}

fn choose_media_type(name: &str, legacy_value: &str) -> (String, MediaTypeSource) {
    let inferred = file_capability::infer_media_type(std::path::Path::new(name));
    match file_capability::normalize_media_type(legacy_value) {
        Ok(normalized)
            if legacy_value.len() == 32
                && inferred != file_capability::DEFAULT_MEDIA_TYPE
                && normalized != inferred =>
        {
            (inferred.to_owned(), MediaTypeSource::FilenameRecovery)
        }
        Ok(normalized) => (normalized, MediaTypeSource::LegacyValue),
        Err(_) if inferred != file_capability::DEFAULT_MEDIA_TYPE => {
            (inferred.to_owned(), MediaTypeSource::FilenameRecovery)
        }
        Err(_) => (
            file_capability::DEFAULT_MEDIA_TYPE.to_owned(),
            MediaTypeSource::GenericDefault,
        ),
    }
}

const INTERVAL_SIGN_BIT: u128 = 1_u128 << 127;

fn i128_to_ordered_be(value: i128) -> [u8; 16] {
    ((value as u128) ^ INTERVAL_SIGN_BIT).to_be_bytes()
}

fn i128_from_ordered_be(bytes: [u8; 16]) -> i128 {
    (u128::from_be_bytes(bytes) ^ INTERVAL_SIGN_BIT) as i128
}

fn reasonable_tai_ns(value: i128) -> bool {
    value > 0 && value < 6_400_000_000_000_000_000
}

/// Convert a timestamp fact written before ordered interval encoding to the
/// current bytes. Some commits already used ordered bytes under the legacy
/// attribute, so classification is semantic rather than attribute-only.
fn canonicalize_legacy_interval(value: Timestamp) -> Result<Timestamp> {
    let lower_le = i128::from_le_bytes(value.raw[0..16].try_into().unwrap());
    let lower_ordered = i128_from_ordered_be(value.raw[0..16].try_into().unwrap());
    match (
        reasonable_tai_ns(lower_le),
        reasonable_tai_ns(lower_ordered),
    ) {
        (true, false) => {
            let lower = lower_le;
            let upper = i128::from_le_bytes(value.raw[16..32].try_into().unwrap());
            let mut raw = [0_u8; 32];
            raw[0..16].copy_from_slice(&i128_to_ordered_be(lower));
            raw[16..32].copy_from_slice(&i128_to_ordered_be(upper));
            Ok(Inline::new(raw))
        }
        (false, true) => Ok(value),
        _ => bail!(
            "legacy import timestamp is encoding-ambiguous (LE={lower_le}, ordered={lower_ordered})"
        ),
    }
}

fn ordered_interval_to_legacy_le(value: Timestamp) -> Timestamp {
    let lower = i128_from_ordered_be(value.raw[0..16].try_into().unwrap());
    let upper = i128_from_ordered_be(value.raw[16..32].try_into().unwrap());
    let mut raw = [0_u8; 32];
    raw[0..16].copy_from_slice(&lower.to_le_bytes());
    raw[16..32].copy_from_slice(&upper.to_le_bytes());
    Inline::new(raw)
}

fn validate_current_interval(value: Timestamp) -> Result<()> {
    let _: (hifitime::Epoch, hifitime::Epoch) = value
        .try_from_inline()
        .map_err(|err| anyhow!("invalid current import timestamp: {err:?}"))?;
    Ok(())
}

fn current_import_identity(record: &ImportRecord) -> Id {
    entity! {
        metadata::tag: &KIND_IMPORT,
        file::root: &record.root,
        file::imported_at: record.imported_at,
        file::source_path: record.source_path,
    }
    .root()
    .expect("import core has a root")
}

fn legacy_import_identity(record: &ImportRecord, imported_at: Timestamp) -> Id {
    entity! {
        metadata::tag: &KIND_IMPORT,
        file::root: &record.root,
        legacy::imported_at: imported_at,
        file::source_path: record.source_path,
    }
    .root()
    .expect("legacy import core has a root")
}

fn ensure_new_ids_are_fixed_points(ids: &BTreeMap<Id, Id>) -> Result<()> {
    for (old, new) in ids {
        if let Some(next) = ids.get(new) {
            if next != new {
                bail!(
                    "non-canonical id map: {old:x} maps to {new:x}, which maps again to {next:x}"
                );
            }
        }
    }
    Ok(())
}

fn mark_core(
    core_attributes: &mut BTreeMap<Id, BTreeSet<Id>>,
    entity: Id,
    attributes: impl IntoIterator<Item = Id>,
) {
    core_attributes
        .entry(entity)
        .or_default()
        .extend(attributes);
}

fn assert_disjoint(label: &str, ids: &BTreeSet<Id>, occupied: &BTreeSet<Id>) -> Result<()> {
    if let Some(id) = ids.intersection(occupied).next() {
        bail!("entity {id:x} is tagged as more than one Files kind (including {label})");
    }
    Ok(())
}

fn raw_genid_target(trible: &Trible) -> Option<Id> {
    trible.v::<GenId>().try_from_inline().ok()
}

fn rewrite_fact(
    trible: &Trible,
    ids: &BTreeMap<Id, Id>,
    references: &BTreeSet<Id>,
    rewrite_subject: bool,
    remapped_subject_facts: &mut usize,
    remapped_reference_facts: &mut usize,
) -> Result<Trible> {
    let mut raw = trible.data;

    if rewrite_subject {
        if let Some(new_subject) = ids.get(trible.e()) {
            if new_subject != trible.e() {
                raw[E_START..=E_END].copy_from_slice(&new_subject[..]);
                *remapped_subject_facts += 1;
            }
        }
    }

    // Only attributes whose schema is known to be GenId are interpreted as
    // references. Inspecting every 32-byte value by shape would corrupt a
    // non-GenId handle that happened to end with the same 16 bytes.
    if references.contains(trible.a()) {
        if let Some(old_target) = raw_genid_target(trible) {
            if let Some(new_target) = ids.get(&old_target) {
                if new_target != &old_target {
                    let value: Inline<GenId> = new_target.to_inline();
                    raw[V_START..=V_END].copy_from_slice(&value.raw);
                    *remapped_reference_facts += 1;
                }
            }
        }
    }

    Trible::force_raw(raw).context("rewritten trible had a nil entity or attribute")
}

fn validate_no_legacy_ids(
    facts: &TribleSet,
    ids: &BTreeMap<Id, Id>,
    references: &BTreeSet<Id>,
    validate_subjects: bool,
) -> Result<()> {
    for trible in facts.iter() {
        if validate_subjects && ids.get(trible.e()).is_some_and(|new| new != trible.e()) {
            bail!("rewritten snapshot still has legacy subject {}", trible.e());
        }
        if references.contains(trible.a()) {
            if let Some(target) = raw_genid_target(trible) {
                if ids.get(&target).is_some_and(|new| new != &target) {
                    bail!(
                        "rewritten snapshot still references legacy entity {target:x} through attribute {:x}",
                        trible.a()
                    );
                }
            }
        }
    }
    Ok(())
}

fn validate_artifact_references(
    facts: &TribleSet,
    ids: &BTreeMap<Id, Id>,
    old_file_ids: &BTreeSet<Id>,
) -> Result<()> {
    let output_files: BTreeSet<Id> = old_file_ids.iter().map(|old| ids[old]).collect();
    let artifact_attributes = artifact_reference_attributes();
    for trible in facts
        .iter()
        .filter(|fact| artifact_attributes.contains(fact.a()))
    {
        let target = raw_genid_target(trible).ok_or_else(|| {
            anyhow!(
                "artifact-reference attribute {:x} contains an invalid GenId",
                trible.a()
            )
        })?;
        if !output_files.contains(&target) {
            bail!(
                "attribute {:x} references file {target:x}, which is absent from the replacement Files lineage",
                trible.a()
            );
        }
    }
    Ok(())
}

fn validate_canonical_files(facts: &TribleSet, expected: usize) -> Result<()> {
    let file_ids: BTreeSet<Id> = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_FILE }])
    )
    .collect();
    if file_ids.len() != expected {
        bail!(
            "rewritten Files snapshot has {} file ids; expected {expected}",
            file_ids.len()
        );
    }
    for id in file_ids {
        let rows: Vec<_> = find!(
            (content: file_capability::ContentHandle, name: NameHandle, media_type: Id, media_name: NameHandle),
            pattern!(facts, [
                { id @ file::content: ?content, file::name: ?name, file::media_type: ?media_type },
                { ?media_type @ metadata::tag: &KIND_MEDIA_TYPE, metadata::name: ?media_name }
            ])
        )
        .collect();
        let (content, name, media_type, _media_name) =
            exactly_one(rows, id, "canonical file core")?;
        let expected_id = entity! {
            metadata::tag: &KIND_FILE,
            file::content: content,
            file::name: name,
            file::media_type: &media_type,
        }
        .root()
        .expect("canonical file core has a root");
        if expected_id != id {
            bail!("canonical file {id:x} does not match its intrinsic core");
        }
    }
    if facts.iter().any(|fact| fact.a() == &legacy::mime.id()) {
        bail!("rewritten Files snapshot still contains legacy file::mime facts");
    }
    Ok(())
}

/// Build a complete replacement snapshot for the Files branch.
///
/// `source` must be a pinned checkout and `source_workspace` must resolve its
/// existing LongString handles. The call performs no writes: newly created
/// media-type/name blobs live inside [`FilesRewrite::content`]. The caller must
/// not append that fragment to the legacy branch; commit it as a new lineage.
pub fn rewrite_files_branch<Blobs: BlobStore>(
    source: &TribleSet,
    source_workspace: &mut Workspace<Blobs>,
) -> Result<FilesRewrite> {
    let mut ids = BTreeMap::new();
    let mut cores = Fragment::empty();
    let mut core_attributes: BTreeMap<Id, BTreeSet<Id>> = BTreeMap::new();
    let mut decisions = Vec::new();
    let mut report = FilesRewriteReport {
        input_tribles: source.len(),
        ..FilesRewriteReport::default()
    };

    let file_ids: BTreeSet<Id> = find!(
        id: Id,
        pattern!(source, [{ ?id @ metadata::tag: &KIND_FILE }])
    )
    .collect();

    for id in &file_ids {
        let legacy_rows: Vec<_> = find!(
            (content: file_capability::ContentHandle, name: NameHandle, mime: String),
            pattern!(source, [{ *id @ file::content: ?content, file::name: ?name, legacy::mime: ?mime }])
        )
        .collect();
        let canonical_rows: Vec<_> = find!(
            (content: file_capability::ContentHandle, name: NameHandle, media_type: Id, media_name: NameHandle),
            pattern!(source, [
                { *id @ file::content: ?content, file::name: ?name, file::media_type: ?media_type },
                { ?media_type @ metadata::tag: &KIND_MEDIA_TYPE, metadata::name: ?media_name }
            ])
        )
        .collect();

        match (legacy_rows.is_empty(), canonical_rows.is_empty()) {
            (false, false) => {
                bail!("file {id:x} carries both legacy file::mime and canonical file::media_type")
            }
            (true, true) => {
                bail!("file {id:x} has neither a complete legacy nor canonical intrinsic core")
            }
            (false, true) => {
                let (content, name, legacy_value) =
                    exactly_one(legacy_rows, *id, "legacy file core")?;
                let old_expected = entity! {
                    metadata::tag: &KIND_FILE,
                    file::content: content,
                    file::name: name,
                    legacy::mime: legacy_value.as_str(),
                }
                .root()
                .expect("legacy file core has a root");
                let old_identity = if old_expected == *id {
                    report.intrinsic_legacy_files += 1;
                    LegacyFileIdentity::Intrinsic
                } else {
                    // Historical Mail, Teams, and Discord adapters forced
                    // source-occurrence ids for their file records. The core
                    // is still singleton-validated above; only the producer's
                    // old identity choice differs.
                    report.forced_legacy_files += 1;
                    LegacyFileIdentity::ForcedSourceId
                };

                let name_text = read_name(source_workspace, name)
                    .with_context(|| format!("read name for legacy file {id:x}"))?;
                let (selected, source_kind) = choose_media_type(&name_text, &legacy_value);
                let fragment =
                    file_capability::fragment_content_handle(content, name_text, &selected)?;
                let new_id = fragment.root().expect("canonical file has a root");
                cores += fragment;
                ids.insert(*id, new_id);
                decisions.push(MediaTypeDecision {
                    old_file: *id,
                    legacy_value,
                    selected,
                    source: source_kind,
                    old_identity,
                });
                match source_kind {
                    MediaTypeSource::FilenameRecovery => report.filename_recoveries += 1,
                    MediaTypeSource::GenericDefault => report.generic_defaults += 1,
                    MediaTypeSource::LegacyValue => {}
                }
                report.legacy_files += 1;
            }
            (true, false) => {
                let (content, name, media_type, media_name) =
                    exactly_one(canonical_rows, *id, "canonical file core")?;
                let stored_name = read_name(source_workspace, media_name)
                    .with_context(|| format!("read media type for canonical file {id:x}"))?;
                let normalized = file_capability::normalize_media_type(&stored_name)?;
                if normalized != stored_name {
                    bail!(
                        "canonical media-type entity {media_type:x} stores non-normalized name {stored_name:?}"
                    );
                }
                let expected_media_type = entity! {
                    metadata::tag: &KIND_MEDIA_TYPE,
                    metadata::name: media_name,
                }
                .root()
                .expect("media type core has a root");
                if expected_media_type != media_type {
                    bail!("media-type entity {media_type:x} does not match its intrinsic core");
                }
                let fragment = entity! {
                    metadata::tag: &KIND_FILE,
                    file::content: content,
                    file::name: name,
                    file::media_type: &media_type,
                };
                if fragment.root() != Some(*id) {
                    bail!("canonical file {id:x} does not match its intrinsic core");
                }
                cores += fragment;
                ids.insert(*id, *id);
                report.canonical_files += 1;
            }
        }

        mark_core(
            &mut core_attributes,
            *id,
            [
                file::content.id(),
                file::name.id(),
                legacy::mime.id(),
                file::media_type.id(),
            ],
        );
    }

    let directory_ids: BTreeSet<Id> = find!(
        id: Id,
        pattern!(source, [{ ?id @ metadata::tag: &KIND_DIRECTORY }])
    )
    .collect();
    assert_disjoint("directory", &directory_ids, &file_ids)?;
    let mut directories = BTreeMap::new();
    for id in &directory_ids {
        let name = exactly_one(
            find!(
                name: NameHandle,
                pattern!(source, [{ *id @ file::name: ?name }])
            )
            .collect(),
            *id,
            "directory name",
        )?;
        let children: BTreeSet<Id> = find!(
            child: Id,
            pattern!(source, [{ *id @ file::children: ?child }])
        )
        .collect();
        let old_expected = entity! {
            metadata::tag: &KIND_DIRECTORY,
            file::name: name,
            file::children*: children.iter(),
        }
        .root()
        .expect("directory core has a root");
        if old_expected != *id {
            bail!("directory {id:x} does not match its intrinsic core");
        }
        directories.insert(*id, DirectoryRecord { name, children });
        mark_core(
            &mut core_attributes,
            *id,
            [file::name.id(), file::children.id()],
        );
    }

    while !directories.is_empty() {
        let ready: Vec<Id> = directories
            .iter()
            .filter(|(_, record)| record.children.iter().all(|child| ids.contains_key(child)))
            .map(|(id, _)| *id)
            .collect();
        if ready.is_empty() {
            let unresolved = directories
                .iter()
                .map(|(id, record)| {
                    let children = record
                        .children
                        .iter()
                        .filter(|child| !ids.contains_key(*child))
                        .map(|child| format!("{child:x}"))
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("{id:x}->[{children}]")
                })
                .collect::<Vec<_>>()
                .join("; ");
            bail!("directory graph is cyclic or has non-file children: {unresolved}");
        }
        for old_id in ready {
            let record = directories.remove(&old_id).expect("ready record exists");
            let mapped_children: Vec<Id> = record.children.iter().map(|child| ids[child]).collect();
            let fragment = entity! {
                metadata::tag: &KIND_DIRECTORY,
                file::name: record.name,
                file::children*: mapped_children.iter(),
            };
            let new_id = fragment.root().expect("directory has a root");
            ids.insert(old_id, new_id);
            cores += fragment;
            report.directories += 1;
        }
    }

    let mut occupied = file_ids.clone();
    occupied.extend(directory_ids.iter().copied());
    let import_ids: BTreeSet<Id> = find!(
        id: Id,
        pattern!(source, [{ ?id @ metadata::tag: &KIND_IMPORT }])
    )
    .collect();
    assert_disjoint("import", &import_ids, &occupied)?;
    for id in &import_ids {
        let root = exactly_one(
            find!(
                root: Id,
                pattern!(source, [{ *id @ file::root: ?root }])
            )
            .collect(),
            *id,
            "import root",
        )?;
        let source_path = exactly_one(
            find!(
                source_path: NameHandle,
                pattern!(source, [{ *id @ file::source_path: ?source_path }])
            )
            .collect(),
            *id,
            "import source path",
        )?;
        let current_timestamp = optional_singleton(
            find!(
                imported_at: Timestamp,
                pattern!(source, [{ *id @ file::imported_at: ?imported_at }])
            )
            .collect(),
            *id,
            "current import timestamp",
        )?;
        let legacy_timestamp = optional_singleton(
            find!(
                imported_at: Timestamp,
                pattern!(source, [{ *id @ legacy::imported_at: ?imported_at }])
            )
            .collect(),
            *id,
            "legacy import timestamp",
        )?;
        if current_timestamp.is_none() && legacy_timestamp.is_none() {
            bail!("import {id:x} has no import timestamp");
        }
        if let Some(current) = current_timestamp {
            validate_current_interval(current)
                .with_context(|| format!("validate timestamp for import {id:x}"))?;
        }
        let normalized_legacy = legacy_timestamp
            .map(canonicalize_legacy_interval)
            .transpose()
            .with_context(|| format!("normalize legacy timestamp for import {id:x}"))?;
        if let (Some(current), Some(from_legacy)) = (current_timestamp, normalized_legacy) {
            if current != from_legacy {
                bail!("import {id:x} has disagreeing legacy and current timestamp facts");
            }
        }
        let imported_at = current_timestamp
            .or(normalized_legacy)
            .expect("one timestamp was required");
        let record = ImportRecord {
            root,
            imported_at,
            source_path,
        };

        // Timestamp migration d834f35 remapped facts without rederiving the
        // import entity. Accept the exact historical LE/ordered identity as
        // well as the current one, but refuse arbitrary forced import ids.
        let mut valid_identities = BTreeSet::from([current_import_identity(&record)]);
        if let Some(raw_legacy) = legacy_timestamp {
            valid_identities.insert(legacy_import_identity(&record, raw_legacy));
        }
        valid_identities.insert(legacy_import_identity(&record, imported_at));
        valid_identities.insert(legacy_import_identity(
            &record,
            ordered_interval_to_legacy_le(imported_at),
        ));
        if !valid_identities.contains(id) {
            bail!("import {id:x} does not match any historical intrinsic core");
        }
        if legacy_timestamp.is_some() || current_import_identity(&record) != *id {
            report.legacy_import_timestamps += 1;
        }

        let new_root = ids.get(&record.root).copied().ok_or_else(|| {
            anyhow!(
                "import {id:x} points at non-file/non-directory root {:x}",
                record.root
            )
        })?;
        let fragment = entity! {
            metadata::tag: &KIND_IMPORT,
            file::root: &new_root,
            file::imported_at: record.imported_at,
            file::source_path: record.source_path,
        };
        let new_id = fragment.root().expect("import has a root");
        ids.insert(*id, new_id);
        cores += fragment;
        mark_core(
            &mut core_attributes,
            *id,
            [
                file::root.id(),
                file::imported_at.id(),
                legacy::imported_at.id(),
                file::source_path.id(),
            ],
        );
        report.imports += 1;
    }

    occupied.extend(import_ids.iter().copied());
    let page_ids: BTreeSet<Id> = find!(
        id: Id,
        pattern!(source, [{ ?id @ metadata::tag: &KIND_PAGE }])
    )
    .collect();
    assert_disjoint("page", &page_ids, &occupied)?;
    for id in &page_ids {
        let record = exactly_one(
            find!(
                (parent: Id, index: String),
                pattern!(source, [{ *id @ page::parent: ?parent, page::index: ?index }])
            )
            .map(|(parent, index)| PageRecord { parent, index })
            .collect(),
            *id,
            "page core",
        )?;
        let old_identity = entity! {
            page::parent: &record.parent,
            page::index: record.index.as_str(),
        };
        if old_identity.root() != Some(*id) {
            bail!("page {id:x} does not match its intrinsic parent/index core");
        }
        let new_parent = ids
            .get(&record.parent)
            .copied()
            .ok_or_else(|| anyhow!("page {id:x} points at unknown file {:x}", record.parent))?;
        let mut fragment = entity! {
            page::parent: &new_parent,
            page::index: record.index.as_str(),
        };
        let new_id = fragment.root().expect("page identity has a root");
        fragment += entity! {
            ExclusiveId::force_ref(&new_id) @ metadata::tag: &KIND_PAGE
        };
        ids.insert(*id, new_id);
        cores += fragment;
        mark_core(
            &mut core_attributes,
            *id,
            [page::parent.id(), page::index.id()],
        );
        report.pages += 1;
    }

    ensure_new_ids_are_fixed_points(&ids)?;
    let references = reference_attributes();
    let mut facts = TribleSet::new();
    for trible in source.iter() {
        if core_attributes
            .get(trible.e())
            .is_some_and(|attributes| attributes.contains(trible.a()))
        {
            continue;
        }
        let rewritten = rewrite_fact(
            trible,
            &ids,
            &references,
            true,
            &mut report.remapped_subject_facts,
            &mut report.remapped_reference_facts,
        )?;
        facts.insert(&rewritten);
    }
    let mut content = cores;
    content += facts;

    report.distinct_output_files = ids
        .iter()
        .filter(|(old, _)| file_ids.contains(*old))
        .map(|(_, new)| *new)
        .collect::<BTreeSet<_>>()
        .len();
    report.output_tribles = content.facts().len();
    validate_no_legacy_ids(content.facts(), &ids, &references, true)?;
    validate_canonical_files(content.facts(), report.distinct_output_files)?;

    Ok(FilesRewrite {
        content,
        ids,
        file_ids,
        decisions,
        report,
    })
}

fn wiki_link_regex() -> &'static Regex {
    static LINK_RE: OnceLock<Regex> = OnceLock::new();
    LINK_RE.get_or_init(|| {
        Regex::new(
            r#"#link\("([a-zA-Z_][a-zA-Z0-9_]*):((?:[a-zA-Z_][a-zA-Z0-9_]*:)?)([0-9a-fA-F]{64}|[0-9a-fA-F]{32})"\)"#,
        )
        .expect("static Wiki link regex")
    })
}

fn typed_wiki_link_attribute(
    prefix: &str,
) -> Option<triblespace::core::attribute::Attribute<GenId>> {
    let type_name = prefix.strip_suffix(':')?;
    if type_name.is_empty() {
        return None;
    }
    let name_handle = type_name.to_owned().to_blob().get_handle();
    Some(triblespace::core::attribute::Attribute::<GenId>::from(
        entity! {
            metadata::name: name_handle,
            metadata::value_encoding: <GenId as triblespace::core::metadata::MetaDescribe>::id(),
        },
    ))
}

/// Rewrite exact Typst `#link` literals without reformatting the surrounding
/// source. The grammar deliberately matches Wiki's reference extractor: a
/// migration must not reinterpret text that the faculty itself does not index
/// as a link.
fn rewrite_wiki_link_literals(
    content: &str,
    files: &FilesRewrite,
) -> (String, usize, BTreeSet<Id>) {
    let mut rewritten = String::with_capacity(content.len());
    let mut cursor = 0;
    let mut literals = 0;
    let mut entities = BTreeSet::new();

    for captures in wiki_link_regex().captures_iter(content) {
        let Some(hex_match) = captures.get(3) else {
            continue;
        };
        if &captures[1] != "files" || hex_match.as_str().len() != 32 {
            continue;
        }
        let Some(old_target) = Id::from_hex(hex_match.as_str()) else {
            continue;
        };
        let Some(new_target) = files.ids.get(&old_target).filter(|new| *new != &old_target) else {
            continue;
        };

        rewritten.push_str(&content[cursor..hex_match.start()]);
        rewritten.push_str(&format!("{new_target:x}"));
        cursor = hex_match.end();
        literals += 1;
        entities.insert(old_target);
    }
    if cursor == 0 {
        return (content.to_owned(), 0, BTreeSet::new());
    }
    rewritten.push_str(&content[cursor..]);
    (rewritten, literals, entities)
}

fn wiki_is_version(source: &TribleSet, id: Id) -> bool {
    exists!(pattern!(source, [{ id @ metadata::tag: &crate::schemas::wiki::KIND_VERSION_ID }]))
}

fn wiki_is_fragment(source: &TribleSet, id: Id) -> bool {
    exists!(pattern!(source, [{ _?version @ wiki::fragment: id }]))
}

fn extract_wiki_references(content: &str, source: &TribleSet, source_version: Id) -> TribleSet {
    let mut edges = TribleSet::new();
    for captures in wiki_link_regex().captures_iter(content) {
        let faculty = &captures[1];
        let type_prefix = &captures[2];
        let hex = captures[3].to_ascii_lowercase();
        match (faculty, hex.len()) {
            ("wiki", 32) => {
                let Some(target) = Id::from_hex(&hex) else {
                    continue;
                };
                if (!wiki_is_version(source, target) && !wiki_is_fragment(source, target))
                    || target == source_version
                {
                    continue;
                }
                edges += entity! {
                    ExclusiveId::force_ref(&source_version) @ wiki::links_to: &target
                };
                if let Some(attribute) = typed_wiki_link_attribute(type_prefix) {
                    edges += entity! {
                        ExclusiveId::force_ref(&source_version) @ attribute: &target
                    };
                }
            }
            ("files", 32) => {
                let Some(target) = Id::from_hex(&hex) else {
                    continue;
                };
                edges += entity! {
                    ExclusiveId::force_ref(&source_version) @ wiki::references_file: &target
                };
            }
            ("files", 64) => {
                let Ok(hash) = inlineencodings::Hash::<inlineencodings::Blake3>::from_hex(&hex)
                else {
                    continue;
                };
                let handle: Inline<Handle<RawBytes>> = Handle::from_hash(hash);
                edges += entity! {
                    ExclusiveId::force_ref(&source_version) @ wiki::references_file_content: handle
                };
            }
            _ => {}
        }
    }
    edges
}

fn timestamp_lower_ns(timestamp: MigrationTimestamp) -> Result<i128> {
    validate_current_interval(timestamp)?;
    Ok(i128_from_ordered_be(
        timestamp.raw[0..16]
            .try_into()
            .expect("interval lower bytes"),
    ))
}

/// Append canonical edits for current Wiki heads against a completed Files
/// plan, preserving every historical version and exact version citation.
///
/// The transform is read-only. `migrated_at` comes from the runner so plan and
/// apply use the same explicit instant; it must be strictly newer than each
/// fragment head that needs an edit. New content blobs live in
/// [`WikiRewrite::additions`].
pub fn rewrite_wiki_heads<Blobs: BlobStore>(
    source: &TribleSet,
    source_workspace: &mut Workspace<Blobs>,
    files: &FilesRewrite,
    migrated_at: MigrationTimestamp,
) -> Result<WikiRewrite> {
    ensure_new_ids_are_fixed_points(&files.ids)?;
    let migrated_lower =
        timestamp_lower_ns(migrated_at).context("validate explicit Wiki migration timestamp")?;
    let mut by_fragment: BTreeMap<Id, Vec<(Id, i128)>> = BTreeMap::new();
    for (version, fragment, created_at) in find!(
        (version: Id, fragment: Id, created_at: Lower),
        pattern!(source, [{
            ?version @
            metadata::tag: &crate::schemas::wiki::KIND_VERSION_ID,
            wiki::fragment: ?fragment,
            metadata::created_at: ?created_at,
        }])
    ) {
        by_fragment
            .entry(fragment)
            .or_default()
            .push((version, created_at.0));
    }

    let mut latest = BTreeMap::new();
    let mut latest_timestamps = BTreeMap::new();
    for (fragment, versions) in &by_fragment {
        let maximum = versions
            .iter()
            .map(|(_, timestamp)| *timestamp)
            .max()
            .expect("fragment group is nonempty");
        let heads: BTreeSet<Id> = versions
            .iter()
            .filter(|(_, timestamp)| *timestamp == maximum)
            .map(|(version, _)| *version)
            .collect();
        if heads.len() != 1 {
            bail!(
                "Wiki fragment {fragment:x} has {} distinct versions tied at its latest timestamp",
                heads.len()
            );
        }
        latest.insert(*fragment, *heads.iter().next().expect("one head"));
        latest_timestamps.insert(*fragment, maximum);
    }

    let mut additions = Fragment::empty();
    let mut edits = BTreeMap::new();
    let mut report = WikiRewriteReport {
        input_tribles: source.len(),
        fragments: latest.len(),
        ..WikiRewriteReport::default()
    };
    let canonical_files_entities: BTreeSet<Id> = files.ids.values().copied().collect();
    for (fragment, old_version) in latest {
        let (title, content) = exactly_one(
            find!(
                (title: NameHandle, content: NameHandle),
                pattern!(source, [{ old_version @ wiki::fragment: fragment, wiki::title: ?title, wiki::content: ?content }])
            )
            .collect(),
            old_version,
            "latest Wiki version core",
        )?;
        let old_text = read_name(source_workspace, content)
            .with_context(|| format!("read content for Wiki version {old_version:x}"))?;
        let (new_text, literal_count, remapped_entities) =
            rewrite_wiki_link_literals(&old_text, files);
        if literal_count == 0 {
            continue;
        }
        if migrated_lower <= latest_timestamps[&fragment] {
            bail!(
                "Wiki migration timestamp is not newer than fragment {fragment:x}'s current head"
            );
        }

        let new_content = additions.put::<LongString, _>(new_text.clone());
        let core = entity! {
            wiki::fragment: &fragment,
            wiki::title: title,
            wiki::content: new_content,
        };
        let new_version = core.root().expect("migrated Wiki version has a root");
        additions += core;

        let mut tags: BTreeSet<Id> = find!(
            tag: Id,
            pattern!(source, [{ old_version @ metadata::tag: ?tag }])
        )
        .collect();
        tags.insert(crate::schemas::wiki::KIND_VERSION_ID);
        additions += entity! {
            ExclusiveId::force_ref(&new_version) @
            metadata::created_at: migrated_at,
            metadata::tag*: tags.iter(),
        };

        let edges = extract_wiki_references(&new_text, source, new_version);
        for target in find!(
            target: Id,
            pattern!(&edges, [{ new_version @ wiki::references_file: ?target }])
        ) {
            if !canonical_files_entities.contains(&target) {
                bail!(
                    "migrated Wiki version {new_version:x} still links to Files entity {target:x}, which is absent from the canonical output"
                );
            }
        }
        additions += edges;
        edits.insert(old_version, new_version);
        report.edited_fragments += 1;
        report.remapped_file_literals += literal_count;
        report.remapped_file_targets += remapped_entities.len();
    }
    report.additions_tribles = additions.facts().len();
    Ok(WikiRewrite {
        additions,
        edits,
        report,
    })
}

/// Rewrite a full non-Wiki branch snapshot using standard Files-reference
/// attributes. Wiki must use [`rewrite_wiki_heads`] because its literal file
/// links participate in version identity.
pub fn rewrite_reference_branch(
    source: &TribleSet,
    files: &FilesRewrite,
) -> Result<ReferenceRewrite> {
    rewrite_reference_branch_with(source, &files.ids, &files.file_ids, std::iter::empty())
}

/// Rewrite a full branch snapshot while explicitly registering additional
/// GenId-valued reference attributes understood by the caller.
pub fn rewrite_reference_branch_with(
    source: &TribleSet,
    ids: &BTreeMap<Id, Id>,
    file_ids: &BTreeSet<Id>,
    additional_reference_attributes: impl IntoIterator<Item = Id>,
) -> Result<ReferenceRewrite> {
    if source.iter().any(|fact| fact.a() == &legacy::mime.id()) {
        bail!("reference snapshot contains legacy file records; use rewrite_files_branch");
    }
    ensure_new_ids_are_fixed_points(ids)?;
    let mut references = reference_attributes();
    references.extend(additional_reference_attributes);
    let mut report = ReferenceRewriteReport {
        input_tribles: source.len(),
        ..ReferenceRewriteReport::default()
    };
    let mut facts = TribleSet::new();
    let mut legacy_occurrence_links = BTreeSet::new();
    for trible in source.iter() {
        if trible.a() == &archive::attachment.id() {
            if let Some(occurrence) = raw_genid_target(trible) {
                if file_ids.contains(&occurrence) {
                    if let Some(new_file) = ids.get(&occurrence) {
                        if new_file != &occurrence {
                            // `archive::attachment` names the occurrence, not
                            // the file. Preserve that edge and make the old
                            // dual-role producer explicit with a new artifact
                            // link from the occurrence.
                            legacy_occurrence_links.insert((occurrence, *new_file));
                        }
                    }
                }
            }
        }
        let rewritten = rewrite_fact(
            trible,
            ids,
            &references,
            false,
            &mut report.remapped_subject_facts,
            &mut report.remapped_reference_facts,
        )?;
        facts.insert(&rewritten);
    }
    for (occurrence, new_file) in legacy_occurrence_links {
        let before = facts.len();
        facts += entity! {
            ExclusiveId::force_ref(&occurrence) @ archive::attachment_file: &new_file
        };
        if facts.len() != before {
            report.occurrence_file_links_added += 1;
        }
    }
    report.output_tribles = facts.len();
    validate_no_legacy_ids(&facts, ids, &references, false)?;
    validate_artifact_references(&facts, ids, file_ids)?;
    Ok(ReferenceRewrite { facts, report })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use rand_core::OsRng;
    use triblespace::core::repo::memoryrepo::MemoryRepo;
    use triblespace::core::repo::Repository;
    use triblespace::prelude::blobencodings::RawBytes;

    fn workspace() -> Workspace<MemoryRepo> {
        let mut repo = Repository::new(
            MemoryRepo::default(),
            SigningKey::generate(&mut OsRng),
            TribleSet::new(),
        )
        .expect("repository");
        let branch = repo.create_branch("migration-test", None).expect("branch");
        repo.pull(*branch).expect("workspace")
    }

    fn legacy_file(
        workspace: &mut Workspace<MemoryRepo>,
        bytes: &[u8],
        name: &str,
        mime: &str,
    ) -> Fragment {
        let content = workspace.put::<RawBytes, _>(bytes.to_vec());
        let name = workspace.put::<LongString, _>(name.to_owned());
        entity! {
            metadata::tag: &KIND_FILE,
            file::content: content,
            file::name: name,
            legacy::mime: mime,
        }
    }

    fn legacy_le_interval(value: i128) -> Timestamp {
        let mut raw = [0_u8; 32];
        raw[0..16].copy_from_slice(&value.to_le_bytes());
        raw[16..32].copy_from_slice(&value.to_le_bytes());
        Inline::new(raw)
    }

    fn current_interval(value: i128) -> Timestamp {
        let mut raw = [0_u8; 32];
        raw[0..16].copy_from_slice(&i128_to_ordered_be(value));
        raw[16..32].copy_from_slice(&i128_to_ordered_be(value));
        Inline::new(raw)
    }

    #[test]
    fn legacy_file_becomes_canonical_and_preserves_exhaust() {
        let mut workspace = workspace();
        let mut source = legacy_file(
            &mut workspace,
            b"deck",
            "slides.pptx",
            "application/vnd.openxmlformats-o",
        );
        let old_file = source.root().unwrap();
        source += entity! {
            ExclusiveId::force_ref(&old_file) @ file::tag: "presentation"
        };

        let rewrite = rewrite_files_branch(&source.into_facts(), &mut workspace).unwrap();
        let new_file = rewrite.ids[&old_file];

        assert_ne!(old_file, new_file);
        assert_eq!(rewrite.report.legacy_files, 1);
        assert_eq!(rewrite.report.filename_recoveries, 1);
        assert_eq!(rewrite.report.distinct_output_files, 1);
        assert_eq!(
            rewrite.decisions[0].source,
            MediaTypeSource::FilenameRecovery
        );
        assert_eq!(
            rewrite.decisions[0].selected,
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        );
        assert!(exists!(pattern!(rewrite.facts(), [
            { new_file @ file::tag: "presentation" }
        ])));
        assert!(!rewrite
            .facts()
            .iter()
            .any(|fact| fact.a() == &legacy::mime.id()));
    }

    #[test]
    fn distinct_media_type_entities_join_to_their_own_files() {
        let mut workspace = workspace();
        let mut source = legacy_file(&mut workspace, b"text", "note.txt", "text/plain");
        source += legacy_file(&mut workspace, b"image", "pixel.png", "image/png");

        let rewrite = rewrite_files_branch(&source.into_facts(), &mut workspace)
            .expect("media entities must join through the file relation");
        assert_eq!(rewrite.report.legacy_files, 2);
        assert_eq!(rewrite.report.distinct_output_files, 2);
        assert_eq!(
            find!(
                id: Id,
                pattern!(rewrite.facts(), [{ ?id @ metadata::tag: &KIND_MEDIA_TYPE }])
            )
            .collect::<BTreeSet<_>>()
            .len(),
            2
        );
    }

    #[test]
    fn merkle_dependents_and_cross_branch_references_follow_the_file() {
        let mut workspace = workspace();
        let mut file_fragment =
            legacy_file(&mut workspace, b"report", "report.pdf", "application/pdf");
        let old_file = file_fragment.root().unwrap();
        let secondary_tag = fucid();
        let secondary_tag_id = *secondary_tag;
        file_fragment += entity! {
            ExclusiveId::force_ref(&old_file) @ metadata::tag: &secondary_tag_id
        };
        let directory_name = workspace.put::<LongString, _>("docs".to_owned());
        let mut directory = entity! {
            metadata::tag: &KIND_DIRECTORY,
            file::name: directory_name,
            file::children*: [old_file],
        };
        let old_directory = directory.root().unwrap();
        directory += entity! {
            ExclusiveId::force_ref(&old_directory) @ metadata::tag: &secondary_tag_id
        };
        let source_path = workspace.put::<LongString, _>("/old/location/docs".to_owned());
        let instant = Epoch::from_unix_seconds(17.0);
        let imported_at: Timestamp = (instant, instant).try_to_inline().unwrap();
        let mut import = entity! {
            metadata::tag: &KIND_IMPORT,
            file::root: &old_directory,
            file::imported_at: imported_at,
            file::source_path: source_path,
        };
        let old_import = import.root().unwrap();
        import += entity! {
            ExclusiveId::force_ref(&old_import) @ metadata::tag: &secondary_tag_id
        };
        let old_timestamp = legacy_le_interval(23);
        let mut legacy_import = entity! {
            metadata::tag: &KIND_IMPORT,
            file::root: &old_directory,
            legacy::imported_at: old_timestamp,
            file::source_path: source_path,
        };
        let old_legacy_import = legacy_import.root().unwrap();
        legacy_import += entity! {
            ExclusiveId::force_ref(&old_legacy_import) @ metadata::tag: &secondary_tag_id
        };
        let mut page_fragment = entity! {
            page::parent: &old_file,
            page::index: "1",
        };
        let old_page = page_fragment.root().unwrap();
        page_fragment += entity! {
            ExclusiveId::force_ref(&old_page) @ metadata::tag: &KIND_PAGE,
            metadata::tag: &secondary_tag_id
        };
        let mut files_source = Fragment::empty();
        files_source += file_fragment;
        files_source += directory;
        files_source += import;
        files_source += legacy_import;
        files_source += page_fragment;

        let files = rewrite_files_branch(&files_source.into_facts(), &mut workspace).unwrap();
        assert_ne!(files.ids[&old_file], old_file);
        assert_ne!(files.ids[&old_directory], old_directory);
        assert_ne!(files.ids[&old_import], old_import);
        assert_ne!(files.ids[&old_legacy_import], old_legacy_import);
        assert_ne!(files.ids[&old_page], old_page);
        assert_eq!(files.report.imports, 2);
        assert_eq!(files.report.legacy_import_timestamps, 1);
        for old in [
            old_file,
            old_directory,
            old_import,
            old_legacy_import,
            old_page,
        ] {
            let new = files.ids[&old];
            assert!(exists!(pattern!(files.facts(), [
                { new @ metadata::tag: &secondary_tag_id }
            ])));
        }

        let message = fucid();
        let message_id = *message;
        let occurrence = fucid();
        let occurrence_id = *occurrence;
        let legacy_message = fucid();
        let legacy_message_id = *legacy_message;
        let mut references = TribleSet::new();
        references += entity! {
            message @ mail::attachment: &old_file
        };
        references += entity! {
            occurrence @ archive::attachment_file: &old_file
        };
        references += entity! {
            legacy_message @ archive::attachment: &old_file
        };
        references += entity! {
            ExclusiveId::force_ref(&old_file) @ metadata::tag: &archive::kind_attachment
        };
        let rewritten = rewrite_reference_branch(&references, &files).unwrap();
        let new_file = files.ids[&old_file];
        assert!(exists!(pattern!(&rewritten.facts, [
            { message_id @ mail::attachment: new_file },
            { occurrence_id @ archive::attachment_file: new_file },
            { legacy_message_id @ archive::attachment: old_file },
            { old_file @ archive::attachment_file: new_file },
            { old_file @ metadata::tag: &archive::kind_attachment }
        ])));
        assert_eq!(rewritten.report.remapped_reference_facts, 2);
        assert_eq!(rewritten.report.occurrence_file_links_added, 1);
        assert_eq!(rewritten.report.remapped_subject_facts, 0);
    }

    #[test]
    fn wiki_migration_appends_a_canonical_head_without_rewriting_history() {
        let mut workspace = workspace();
        let legacy = legacy_file(&mut workspace, b"paper", "paper.pdf", "application/pdf");
        let old_file = legacy.root().unwrap();
        let files = rewrite_files_branch(&legacy.into_facts(), &mut workspace).unwrap();
        let new_file = files.ids[&old_file];

        let target_fragment = *fucid();
        let target_title = workspace.put::<LongString, _>("Target".to_owned());
        let target_content = workspace.put::<LongString, _>("target body".to_owned());
        let target_core = entity! {
            wiki::fragment: &target_fragment,
            wiki::title: target_title,
            wiki::content: target_content,
        };
        let target_version = target_core.root().unwrap();

        let fragment = *fucid();
        let title = workspace.put::<LongString, _>("Source".to_owned());
        let content_hash = "0".repeat(64);
        let old_text = format!(
            "#link(\"files:{old_file:x}\") and #link(\"files:{old_file:x}\") \
             #link(\"files:{content_hash}\") #link(\"wiki:evidence:{target_version:x}\")"
        );
        let old_content = workspace.put::<LongString, _>(old_text.clone());
        let old_core = entity! {
            wiki::fragment: &fragment,
            wiki::title: title,
            wiki::content: old_content,
        };
        let old_version = old_core.root().unwrap();
        let inherited_tag = *fucid();
        let mut source = TribleSet::new();
        source += target_core;
        source += entity! {
            ExclusiveId::force_ref(&target_version) @
            metadata::created_at: current_interval(10),
            metadata::tag: &crate::schemas::wiki::KIND_VERSION_ID,
        };
        source += old_core;
        source += entity! {
            ExclusiveId::force_ref(&old_version) @
            metadata::created_at: current_interval(20),
            metadata::tag: &crate::schemas::wiki::KIND_VERSION_ID,
            metadata::tag: &inherited_tag,
            file::tag: "stale derived state",
        };
        source += extract_wiki_references(&old_text, &source, old_version);

        let timestamp_error =
            rewrite_wiki_heads(&source, &mut workspace, &files, current_interval(20))
                .expect_err("the appended head must sort after the old one");
        assert!(timestamp_error.to_string().contains("not newer"));
        let rewrite = rewrite_wiki_heads(&source, &mut workspace, &files, current_interval(30))
            .expect("Wiki head rewrite");
        let new_version = rewrite.edits[&old_version];
        assert_ne!(new_version, old_version);
        assert_eq!(rewrite.report.fragments, 2);
        assert_eq!(rewrite.report.edited_fragments, 1);
        assert_eq!(rewrite.report.remapped_file_literals, 2);
        assert_eq!(rewrite.report.remapped_file_targets, 1);
        assert!(exists!(pattern!(&source, [
            { old_version @ wiki::references_file: old_file },
            { old_version @ file::tag: "stale derived state" }
        ])));
        assert!(exists!(pattern!(rewrite.facts(), [
            { new_version @
                wiki::fragment: fragment,
                metadata::tag: &crate::schemas::wiki::KIND_VERSION_ID,
                metadata::tag: &inherited_tag,
                wiki::references_file: new_file,
                wiki::links_to: target_version,
            }
        ])));
        assert!(!exists!(pattern!(rewrite.facts(), [
            { new_version @ file::tag: "stale derived state" }
        ])));
        let typed_attribute = typed_wiki_link_attribute("evidence:").unwrap().id();
        assert!(rewrite.facts().iter().any(|fact| {
            fact.e() == &new_version
                && fact.a() == &typed_attribute
                && raw_genid_target(fact) == Some(target_version)
        }));

        let new_content = exactly_one(
            find!(
                content: NameHandle,
                pattern!(rewrite.facts(), [{ new_version @ wiki::content: ?content }])
            )
            .collect(),
            new_version,
            "migrated content",
        )
        .unwrap();
        let expected_core = entity! {
            wiki::fragment: &fragment,
            wiki::title: title,
            wiki::content: new_content,
        };
        assert_eq!(expected_core.root(), Some(new_version));

        workspace.commit(rewrite.additions.clone(), "stage Wiki additions");
        let new_text = read_name(&mut workspace, new_content).unwrap();
        assert_eq!(new_text.matches(&format!("files:{new_file:x}")).count(), 2);
        assert!(new_text.contains(&format!("files:{content_hash}")));
        assert!(new_text.contains(&format!("wiki:evidence:{target_version:x}")));

        let mut migrated_source = source.clone();
        migrated_source += rewrite.additions.into_facts();
        let second = rewrite_wiki_heads(
            &migrated_source,
            &mut workspace,
            &files,
            current_interval(30),
        )
        .expect("rerun is a fixed point");
        assert!(second.edits.is_empty());
        assert!(second.facts().is_empty());
    }

    #[test]
    fn wiki_tied_latest_heads_are_rejected_deterministically() {
        let mut workspace = workspace();
        let legacy = legacy_file(&mut workspace, b"paper", "paper.pdf", "application/pdf");
        let files = rewrite_files_branch(&legacy.into_facts(), &mut workspace).unwrap();
        let fragment = *fucid();
        let mut source = TribleSet::new();
        for (title_text, content_text) in [("First", "one"), ("Second", "two")] {
            let title = workspace.put::<LongString, _>(title_text.to_owned());
            let content = workspace.put::<LongString, _>(content_text.to_owned());
            let core = entity! {
                wiki::fragment: &fragment,
                wiki::title: title,
                wiki::content: content,
            };
            let version = core.root().unwrap();
            source += core;
            source += entity! {
                ExclusiveId::force_ref(&version) @
                metadata::created_at: current_interval(20),
                metadata::tag: &crate::schemas::wiki::KIND_VERSION_ID,
            };
        }

        let error = rewrite_wiki_heads(&source, &mut workspace, &files, current_interval(30))
            .expect_err("latest ties need operator arbitration");
        assert!(error.to_string().contains("tied at its latest timestamp"));
    }

    #[test]
    fn unknown_value_shapes_are_untouched_until_the_attribute_is_registered() {
        let old = *fucid();
        let new = *fucid();
        let subject = fucid();
        let unknown_attribute = *fucid();
        let mut ids = BTreeMap::new();
        ids.insert(old, new);
        let mut source = TribleSet::new();
        let old_value: Inline<GenId> = old.to_inline();
        source.insert(&Trible::force(&subject, &unknown_attribute, &old_value));

        let file_ids = BTreeSet::from([old]);
        let untouched =
            rewrite_reference_branch_with(&source, &ids, &file_ids, std::iter::empty()).unwrap();
        assert_eq!(untouched.report.remapped_reference_facts, 0);
        assert_eq!(untouched.facts, source);

        let rewritten =
            rewrite_reference_branch_with(&source, &ids, &file_ids, [unknown_attribute]).unwrap();
        assert_eq!(rewritten.report.remapped_reference_facts, 1);
        let fact = rewritten.facts.iter().next().expect("rewritten fact");
        assert_eq!(fact.e(), &*subject);
        assert_eq!(fact.a(), &unknown_attribute);
        assert_eq!(raw_genid_target(fact), Some(new));
    }

    #[test]
    fn dangling_known_artifact_references_abort_the_branch_plan() {
        let old = *fucid();
        let new = *fucid();
        let missing = *fucid();
        let message = fucid();
        let mut ids = BTreeMap::new();
        ids.insert(old, new);
        let file_ids = BTreeSet::from([old]);
        let source = entity! {
            message @ mail::attachment: &missing
        }
        .into_facts();

        let error = rewrite_reference_branch_with(&source, &ids, &file_ids, std::iter::empty())
            .expect_err("dangling standard file references must fail validation");
        assert!(error
            .to_string()
            .contains("absent from the replacement Files lineage"));
    }

    #[test]
    fn canonical_output_is_a_fixed_point() {
        let mut workspace = workspace();
        let source = legacy_file(&mut workspace, b"plain", "note.txt", "TEXT/PLAIN");
        let first = rewrite_files_branch(&source.into_facts(), &mut workspace).unwrap();
        workspace.commit(first.content.clone(), "stage first rewrite");
        let second = rewrite_files_branch(first.facts(), &mut workspace).unwrap();

        assert_eq!(first.facts(), second.facts());
        assert_eq!(second.report.legacy_files, 0);
        assert_eq!(second.report.canonical_files, 1);
        assert!(second.ids.iter().all(|(old, new)| old == new));
    }

    #[test]
    fn historical_forced_file_ids_are_rebuilt_and_reported() {
        let mut workspace = workspace();
        let good = legacy_file(
            &mut workspace,
            b"data",
            "data.bin",
            "application/octet-stream",
        );
        let wrong = fucid();
        let mut malformed = TribleSet::new();
        for fact in good.iter() {
            let mut raw = fact.data;
            raw[E_START..=E_END].copy_from_slice(&wrong[..]);
            malformed.insert(&Trible::force_raw(raw).unwrap());
        }

        let rewrite = rewrite_files_branch(&malformed, &mut workspace).unwrap();
        assert_eq!(rewrite.report.intrinsic_legacy_files, 0);
        assert_eq!(rewrite.report.forced_legacy_files, 1);
        assert_eq!(
            rewrite.decisions[0].old_identity,
            LegacyFileIdentity::ForcedSourceId
        );
        assert_ne!(rewrite.ids[&*wrong], *wrong);
    }

    #[test]
    fn equivalent_historical_file_ids_converge_and_union_exhaust() {
        let mut workspace = workspace();
        let mut intrinsic = legacy_file(&mut workspace, b"same", "same.txt", "text/plain");
        let intrinsic_id = intrinsic.root().unwrap();
        intrinsic += entity! {
            ExclusiveId::force_ref(&intrinsic_id) @ file::tag: "intrinsic"
        };

        let forced_id = fucid();
        let mut forced = TribleSet::new();
        for fact in intrinsic.iter() {
            if fact.a() == &file::tag.id() {
                continue;
            }
            let mut raw = fact.data;
            raw[E_START..=E_END].copy_from_slice(&forced_id[..]);
            forced.insert(&Trible::force_raw(raw).unwrap());
        }
        forced += entity! {
            ExclusiveId::force_ref(&forced_id) @ file::tag: "forced"
        };

        let mut source = intrinsic.into_facts();
        source += forced;
        let rewrite = rewrite_files_branch(&source, &mut workspace).unwrap();
        let canonical = rewrite.ids[&intrinsic_id];

        assert_eq!(rewrite.ids[&*forced_id], canonical);
        assert_eq!(rewrite.report.legacy_files, 2);
        assert_eq!(rewrite.report.distinct_output_files, 1);
        assert!(exists!(pattern!(rewrite.facts(), [
            { canonical @ file::tag: "intrinsic" },
            { canonical @ file::tag: "forced" }
        ])));
    }

    #[test]
    fn dangling_directory_children_abort_the_plan() {
        let mut workspace = workspace();
        let missing_child = fucid();
        let name = workspace.put::<LongString, _>("broken".to_owned());
        let directory = entity! {
            metadata::tag: &KIND_DIRECTORY,
            file::name: name,
            file::children*: [*missing_child],
        };

        let error = rewrite_files_branch(&directory.into_facts(), &mut workspace)
            .expect_err("dangling children must not produce a partial plan");
        assert!(error.to_string().contains("non-file children"));
    }

    #[test]
    fn trible_layout_constants_stay_aligned_with_raw_rewrite() {
        assert_eq!((E_START, E_END), (0, 15));
        assert_eq!((A_START, A_END), (16, 31));
        assert_eq!((V_START, V_END), (32, 63));
    }
}
