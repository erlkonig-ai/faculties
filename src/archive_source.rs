//! Shared zero-copy source-adapter substrate for Archive transcript importers.
//!
//! Source adapters own only format knowledge: they scan immutable bytes into
//! [`SourceRecord`]s whose strings and raw records remain views of the source
//! allocation. This module owns source-DAG validation, transparent-node
//! contraction, content construction, source receipts, and callback emission.
//! No adapter needs a dynamic JSON tree, repository head, branch, or cursor.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anybytes::{ByteArea, Bytes, View};
use anyhow::{bail, Context, Result};
use triblespace::core::import::scanner as sc;
use triblespace::prelude::inlineencodings::NsTAIInterval;
use triblespace::prelude::*;

use crate::blockdag::{self, ProjectionAnnotations};
use crate::schemas::blockdag as schema;

/// One immutable, disk-backed copy of a potentially live source prefix.
///
/// `digest` is ephemeral mutation-detection evidence for a multi-pass adapter;
/// exact durable identity comes from [`source_snapshot_fragment`]'s ordered
/// content-addressed chunks.
#[derive(Clone, Debug)]
pub struct FrozenSource {
    pub bytes: Bytes,
    pub digest: [u8; 32],
}

/// Freeze the file size observed from one open handle.
pub fn freeze_file(path: &Path) -> Result<FrozenSource> {
    let mut source =
        File::open(path).with_context(|| format!("open {} for freezing", path.display()))?;
    let len = source
        .metadata()
        .with_context(|| format!("stat {} for freezing", path.display()))?
        .len();
    freeze_open_file(&mut source, path, len)
}

/// Freeze exactly `len` leading bytes from a potentially growing file.
pub fn freeze_prefix(path: &Path, len: u64) -> Result<FrozenSource> {
    let mut source =
        File::open(path).with_context(|| format!("open {} for freezing", path.display()))?;
    freeze_open_file(&mut source, path, len)
}

fn freeze_open_file(source: &mut File, path: &Path, len: u64) -> Result<FrozenSource> {
    let len = usize::try_from(len).with_context(|| {
        format!(
            "source prefix for {} does not fit this platform's address space",
            path.display()
        )
    })?;
    if len == 0 {
        return Ok(FrozenSource {
            bytes: Bytes::empty(),
            digest: *blake3::hash(&[]).as_bytes(),
        });
    }
    let mut area = ByteArea::new().context("create private source freeze area")?;
    let mut sections = area.sections();
    let mut section = sections
        .reserve::<u8>(len)
        .context("reserve source freeze area")?;
    source
        .read_exact(&mut section)
        .with_context(|| format!("freeze {len} bytes from {}", path.display()))?;
    let digest = *blake3::hash(&section).as_bytes();
    let bytes = section
        .freeze()
        .with_context(|| format!("make frozen source {} immutable", path.display()))?;
    Ok(FrozenSource { bytes, digest })
}

/// Represent one exact frozen source as a self-describing snapshot value.
///
/// Fixed-size byte chunks are source-format agnostic and may split UTF-8 or a
/// JSON record. Their intrinsic handles are reused across append-only imports;
/// the snapshot root preserves which ordered set and exact length coexisted.
pub fn source_snapshot_fragment(
    namespace: Id,
    anchor: &str,
    source_path: &Path,
    bytes: &Bytes,
) -> Result<(Fragment, usize)> {
    let mut chunks = Fragment::empty();
    let mut count = 0usize;
    for offset in (0..bytes.len()).step_by(schema::source_chunk::CANONICAL_BYTES) {
        let end = offset
            .saturating_add(schema::source_chunk::CANONICAL_BYTES)
            .min(bytes.len());
        chunks += blockdag::source_chunk(offset as u128, bytes.slice(offset..end))?;
        count += 1;
    }
    let length = u128::try_from(bytes.len()).expect("usize always fits u128");
    let snapshot = blockdag::source_snapshot(
        namespace,
        format!("snapshot/v1/{anchor}"),
        length,
        chunks,
        Some(source_path.to_string_lossy().into_owned()),
    )?;
    Ok((snapshot, count))
}

/// Whether an occurrence participates in the canonical dialogue DAG.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Threading {
    /// The projected block is a semantic predecessor for source children.
    #[default]
    Semantic,
    /// Retain the occurrence, but contract it out of semantic predecessor paths.
    Transparent,
}

/// One ordered semantic datum extracted from a source occurrence.
#[derive(Clone, Debug)]
pub enum SourcePart {
    /// UTF-8 text, thinking, event, or textual tool payload.
    Text {
        modality: Id,
        direction: Id,
        value: View<str>,
    },
    /// Resident binary payload.
    Blob {
        modality: Id,
        direction: Id,
        bytes: Bytes,
        media_type: View<str>,
    },
    /// External asset, optionally accompanied by recovered bytes.
    Pointer {
        modality: Id,
        direction: Id,
        namespace: Id,
        pointer: View<str>,
        media_type: Option<View<str>>,
        size: Option<u128>,
        resolved: Option<Bytes>,
    },
}

impl SourcePart {
    /// Construct a text part without copying its backing source allocation.
    pub fn text(modality: Id, direction: Id, value: View<str>) -> Self {
        Self::Text {
            modality,
            direction,
            value,
        }
    }
}

/// Parsed claims that remain occurrence-scoped rather than entering block ID.
#[derive(Clone, Debug, Default)]
pub struct SourceClaims {
    pub timestamp: Option<Inline<NsTAIInterval>>,
    pub author: Option<Id>,
    pub experiencer: Option<Id>,
    pub raw_author: Option<View<str>>,
    pub raw_role: Option<View<str>>,
    pub raw_model: Option<View<str>>,
}

/// One exact source occurrence plus its semantic interpretation.
#[derive(Clone, Debug)]
pub struct SourceRecord {
    /// Vendor-stable locator, scoped by the adapter namespace.
    pub locator: View<str>,
    /// Exact source bytes for this occurrence, never a reserialization.
    pub raw_record: Bytes,
    /// Source locators whose nearest semantic projections precede this one.
    pub predecessors: Vec<View<str>>,
    /// Optional stable timestamp that genuinely belongs in semantic block ID.
    pub block_timestamp: Option<Inline<NsTAIInterval>>,
    /// Whether children see this record in their semantic predecessor frontier.
    pub threading: Threading,
    /// Ordered semantic content. Empty records remain source-only receipts.
    ///
    /// Adapters that intentionally expose a raw source event must add an
    /// explicit `EVENT` part. Provenance bytes are never promoted into
    /// searchable semantic content implicitly.
    pub parts: Vec<SourcePart>,
    /// Nonidentity source claims.
    pub claims: SourceClaims,
}

/// One source-only fragment emitted to an Archive import writer.
pub struct ProjectedSource {
    pub source_path: PathBuf,
    pub fragment: Fragment,
}

/// Common accounting across source adapters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProjectionStats {
    pub records_seen: usize,
    pub projections_emitted: usize,
    pub content_parts: usize,
    pub transparent_records: usize,
    pub raw_only_records: usize,
    pub missing_predecessors: usize,
}

/// Map a user-supplied immutable export into one shareable byte owner.
///
/// `anybytes` keeps the mapping alive for every derived `Bytes` and `View`, but
/// the file itself must not be concurrently modified. Live logs and editor
/// state must use [`read_file`] or a line-buffered scanner instead.
pub fn map_immutable_file(path: &Path) -> Result<Bytes> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let len = file
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    if len == 0 {
        return Ok(Bytes::empty());
    }
    // SAFETY: this API is intentionally restricted to immutable data exports.
    // The returned Bytes owns the mmap, so derived views cannot outlive it.
    unsafe { Bytes::map_file(&file) }.with_context(|| format!("mmap {}", path.display()))
}

/// Read a potentially mutable source into one immutable shareable allocation.
pub fn read_file(path: &Path) -> Result<Bytes> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(Bytes::from_source(bytes))
}

/// Parse a JSON string directly into a source-backed UTF-8 view.
pub fn string(bytes: &mut Bytes) -> std::result::Result<View<str>, sc::ScanError> {
    sc::parse_string(bytes)?
        .view::<str>()
        .map_err(|_| sc::ScanError::Syntax("JSON string is not UTF-8".to_owned()))
}

/// Capture one exact JSON value as a zero-copy slice while advancing input.
pub fn raw_value(bytes: &mut Bytes) -> std::result::Result<Bytes, sc::ScanError> {
    sc::take_value(bytes)
}

/// Canonicalize one JSON value without constructing a dynamic value tree.
///
/// Arrays stream in source order. Objects alone require temporary storage so
/// decoded keys can be sorted; duplicate keys retain their final value. This
/// deliberately freezes the historical dynamic-tree spelling used by Archive
/// tool payloads while keeping parsing source-backed and scanner-native.
pub fn canonical_json(mut bytes: Bytes) -> std::result::Result<String, sc::ScanError> {
    sc::skip_ws(&mut bytes);
    let canonical = canonical_json_value(&mut bytes)?;
    sc::skip_ws(&mut bytes);
    if !bytes.is_empty() {
        return Err(sc::ScanError::Syntax(
            "trailing bytes after canonical JSON value".to_owned(),
        ));
    }
    Ok(canonical)
}

fn canonical_json_value(bytes: &mut Bytes) -> std::result::Result<String, sc::ScanError> {
    match bytes.first().copied() {
        Some(b'"') => Ok(canonical_json_string(string(bytes)?.as_ref())),
        Some(b'{') => {
            let members = sc::object(
                bytes,
                BTreeMap::<String, String>::new(),
                |mut members, key, value| {
                    let key = key.view::<str>().map_err(|_| {
                        sc::ScanError::Syntax("JSON object key is not UTF-8".to_owned())
                    })?;
                    members.insert(key.as_ref().to_owned(), canonical_json_value(value)?);
                    Ok(members)
                },
            )?;
            let mut out = String::from("{");
            for (ordinal, (key, value)) in members.into_iter().enumerate() {
                if ordinal != 0 {
                    out.push(',');
                }
                out.push_str(&canonical_json_string(&key));
                out.push(':');
                out.push_str(&value);
            }
            out.push('}');
            Ok(out)
        }
        Some(b'[') => {
            let values = sc::array(bytes, String::new(), |mut out, value| {
                if !out.is_empty() {
                    out.push(',');
                }
                out.push_str(&canonical_json_value(value)?);
                Ok(out)
            })?;
            Ok(format!("[{values}]"))
        }
        Some(b't') => {
            sc::expect_literal(bytes, b"true")?;
            Ok("true".to_owned())
        }
        Some(b'f') => {
            sc::expect_literal(bytes, b"false")?;
            Ok("false".to_owned())
        }
        Some(b'n') => {
            sc::expect_literal(bytes, b"null")?;
            Ok("null".to_owned())
        }
        Some(_) => canonical_json_number(sc::parse_number(bytes)?),
        None => Err(sc::ScanError::Syntax("expected JSON value".to_owned())),
    }
}

fn canonical_json_number(raw: Bytes) -> std::result::Result<String, sc::ScanError> {
    let raw = raw
        .view::<str>()
        .map_err(|_| sc::ScanError::Syntax("JSON number is not UTF-8".to_owned()))?;
    let raw = raw.as_ref();
    if !raw.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
        if raw.starts_with('-') {
            if raw != "-0" {
                if let Ok(value) = raw.parse::<i64>() {
                    return Ok(value.to_string());
                }
            }
        } else if let Ok(value) = raw.parse::<u64>() {
            return Ok(value.to_string());
        }
    }
    let value = raw
        .parse::<f64>()
        .map_err(|_| sc::ScanError::Syntax("invalid JSON number".to_owned()))?;
    if !value.is_finite() {
        return Err(sc::ScanError::Syntax(
            "JSON number is out of range".to_owned(),
        ));
    }
    Ok(zmij::Buffer::new().format_finite(value).to_owned())
}

/// Return the canonical JSON spelling of one decoded string.
pub fn canonical_json_string(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            control if control <= '\u{1f}' => {
                let byte = control as u8;
                out.push_str("\\u00");
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0x0f) as usize] as char);
            }
            character => out.push(character),
        }
    }
    out.push('"');
    out
}

/// Convert computed UTF-8 into the same view type used by source slices.
pub fn owned_text(value: impl Into<String>) -> View<str> {
    Bytes::from_source(value.into())
        .view::<str>()
        .expect("String is valid UTF-8")
}

/// Pick a canonical binary modality from a MIME spelling.
pub fn modality_for_media_type(media_type: &str) -> Id {
    if media_type.starts_with("image/") {
        schema::content_fact::modality::IMAGE
    } else if media_type.starts_with("audio/") {
        schema::content_fact::modality::AUDIO
    } else if media_type.starts_with("video/") {
        schema::content_fact::modality::VIDEO
    } else {
        schema::content_fact::modality::FILE
    }
}

fn build_fact(part: SourcePart) -> Result<Fragment> {
    match part {
        SourcePart::Text {
            modality,
            direction,
            value,
        } => blockdag::text_fact_view(modality, direction, value),
        SourcePart::Blob {
            modality,
            direction,
            bytes,
            media_type,
        } => blockdag::blob_fact(modality, direction, bytes, media_type.as_ref()),
        SourcePart::Pointer {
            modality,
            direction,
            namespace,
            pointer,
            media_type,
            size,
            resolved,
        } => {
            let fact = blockdag::asset_pointer_fact_view(
                modality,
                direction,
                namespace,
                pointer,
                media_type.as_ref().map(AsRef::as_ref),
                size,
            )?;
            match resolved {
                Some(bytes) => blockdag::resolve_pointer_fact(fact, bytes),
                None => Ok(fact),
            }
        }
    }
}

/// Project a complete source graph through the canonical block-DAG model.
///
/// The graph is planned before fragments are emitted. Output is independent of
/// source iteration order, and transparent envelope nodes are contracted by
/// the set of nearest semantic ancestors rather than historical path.
pub fn project_records<F>(
    source_namespace: Id,
    source_path: &Path,
    records: Vec<SourceRecord>,
    mut emit: F,
) -> Result<ProjectionStats>
where
    F: FnMut(ProjectedSource) -> Result<()>,
{
    let mut by_locator = HashMap::<View<str>, usize>::with_capacity(records.len());
    for (index, record) in records.iter().enumerate() {
        if by_locator.insert(record.locator.clone(), index).is_some() {
            bail!("duplicate source locator {:?}", record.locator.as_ref());
        }
    }

    let mut stats = ProjectionStats {
        records_seen: records.len(),
        ..ProjectionStats::default()
    };
    let mut indegree = vec![0usize; records.len()];
    let mut children = vec![Vec::<usize>::new(); records.len()];
    for (index, record) in records.iter().enumerate() {
        let mut unique = BTreeSet::new();
        for predecessor in &record.predecessors {
            if let Some(&parent) = by_locator.get(predecessor) {
                if unique.insert(parent) {
                    indegree[index] += 1;
                    children[parent].push(index);
                }
            } else {
                stats.missing_predecessors += 1;
            }
        }
    }

    let mut ready: Vec<usize> = indegree
        .iter()
        .enumerate()
        .filter_map(|(index, count)| (*count == 0).then_some(index))
        .collect();
    sort_ready(&mut ready, &records);
    let mut order = Vec::with_capacity(records.len());
    while let Some(index) = ready.pop() {
        order.push(index);
        for &child in &children[index] {
            indegree[child] -= 1;
            if indegree[child] == 0 {
                ready.push(child);
                sort_ready(&mut ready, &records);
            }
        }
    }
    if order.len() != records.len() {
        bail!("source predecessor graph contains a cycle");
    }

    let mut semantic_frontiers = vec![BTreeSet::<usize>::new(); records.len()];
    let mut block_ids = vec![None::<Id>; records.len()];
    let mut projection_ids = vec![None::<Id>; records.len()];

    for index in order {
        let record = &records[index];
        // A raw-only record projects to the canonical bottom block and is
        // contracted from semantic history regardless of an adapter's nominal
        // threading preference. Its timestamp remains an occurrence claim.
        let semantic_frontier_member =
            record.threading == Threading::Semantic && !record.parts.is_empty();
        let mut predecessor_indices = BTreeSet::new();
        for predecessor in &record.predecessors {
            if let Some(&parent) = by_locator.get(predecessor) {
                predecessor_indices.extend(semantic_frontiers[parent].iter().copied());
            }
        }

        let mut parts = Fragment::empty();
        if record.parts.is_empty() {
            stats.raw_only_records += 1;
        }
        for (ordinal, part) in record.parts.iter().cloned().enumerate() {
            let ordinal = u64::try_from(ordinal).context("content-part ordinal exceeds u64")?;
            parts += blockdag::content_part(ordinal, build_fact(part)?, None)?;
            stats.content_parts += 1;
        }

        let predecessors: Vec<Id> = if semantic_frontier_member {
            predecessor_indices
                .iter()
                .map(|parent| {
                    block_ids[*parent].expect("semantic frontier contains a projected block")
                })
                .collect()
        } else {
            Vec::new()
        };
        let block_timestamp = (!record.parts.is_empty())
            .then_some(record.block_timestamp)
            .flatten();
        let block = blockdag::block(predecessors, block_timestamp, parts)?;
        let block_id = block.root().expect("canonical block is rooted");
        let projection = blockdag::source_projection_view(
            source_namespace,
            record.locator.clone(),
            record.raw_record.clone(),
            block,
        )?;
        let predecessor_support: Vec<Id> = if semantic_frontier_member {
            predecessor_indices
                .iter()
                .map(|parent| {
                    projection_ids[*parent].expect("semantic frontier contains a source projection")
                })
                .collect()
        } else {
            Vec::new()
        };
        let projection = blockdag::annotate_source_projection(
            projection,
            ProjectionAnnotations {
                semantic_predecessor_support: predecessor_support,
                source_timestamp: record.claims.timestamp,
                author: record.claims.author,
                experiencer: record.claims.experiencer,
                raw_author: record
                    .claims
                    .raw_author
                    .as_ref()
                    .map(|value| value.as_ref().to_owned()),
                raw_role: record
                    .claims
                    .raw_role
                    .as_ref()
                    .map(|value| value.as_ref().to_owned()),
                raw_model: record
                    .claims
                    .raw_model
                    .as_ref()
                    .map(|value| value.as_ref().to_owned()),
                source_path: Some(source_path.display().to_string()),
            },
        )?;
        let projection_id = projection
            .root()
            .expect("canonical source projection is rooted");
        emit(ProjectedSource {
            source_path: source_path.to_path_buf(),
            fragment: projection,
        })?;

        block_ids[index] = Some(block_id);
        projection_ids[index] = Some(projection_id);
        if semantic_frontier_member {
            semantic_frontiers[index].insert(index);
        } else {
            stats.transparent_records += 1;
            semantic_frontiers[index] = predecessor_indices;
        }
        stats.projections_emitted += 1;
    }

    Ok(stats)
}

fn sort_ready(ready: &mut [usize], records: &[SourceRecord]) {
    ready.sort_by(|left, right| {
        records[*right]
            .locator
            .as_ref()
            .cmp(records[*left].locator.as_ref())
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(
        locator: &str,
        predecessors: &[&str],
        threading: Threading,
        text: Option<&str>,
    ) -> SourceRecord {
        SourceRecord {
            locator: owned_text(locator),
            raw_record: Bytes::from_source(format!(r#"{{"locator":"{locator}"}}"#)),
            predecessors: predecessors.iter().copied().map(owned_text).collect(),
            block_timestamp: None,
            threading,
            parts: text
                .map(|value| {
                    vec![SourcePart::text(
                        schema::content_fact::modality::TEXT,
                        schema::content_fact::direction::AMBIENT,
                        owned_text(value),
                    )]
                })
                .unwrap_or_default(),
            claims: SourceClaims::default(),
        }
    }

    fn projected_block(fragment: &Fragment) -> Id {
        let projection = fragment.root().expect("projection has one root");
        find!(
            (block: Id),
            pattern!(fragment, [{
                projection @ schema::source_projection::projects_to: ?block
            }])
        )
        .next()
        .map(|(block,)| block)
        .expect("projection names one block")
    }

    #[test]
    fn transparent_nodes_contract_to_the_same_semantic_future() {
        let records = vec![
            record("child", &["envelope"], Threading::Semantic, Some("b")),
            record("envelope", &["root"], Threading::Transparent, None),
            record("root", &[], Threading::Semantic, Some("a")),
        ];
        let mut emitted = Vec::new();
        let stats = project_records(
            schema::source_projection::SOURCE_AGY,
            Path::new("fixture.json"),
            records,
            |projected| {
                emitted.push(projected.fragment);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(stats.projections_emitted, 3);
        assert_eq!(stats.transparent_records, 1);
        assert_eq!(stats.raw_only_records, 1);
        assert_eq!(stats.content_parts, 2);
        let root_projection = emitted[0].root().unwrap();
        let root_block = projected_block(&emitted[0]);
        let envelope_block = projected_block(&emitted[1]);
        let child_block = projected_block(&emitted[2]);
        assert!(!exists!(pattern!(&emitted[1], [{
            envelope_block @ schema::block::contains: _?part
        }])));
        assert!(exists!(pattern!(&emitted[2], [{
            child_block @ schema::block::previous: root_block
        }])));
        assert!(exists!(pattern!(&emitted[2], [{
            _?projection @ schema::source_projection::semantic_predecessor_support:
                root_projection
        }])));
    }

    #[test]
    fn cycles_fail_before_the_first_fragment_is_emitted() {
        let records = vec![
            record("a", &["b"], Threading::Semantic, Some("a")),
            record("b", &["a"], Threading::Semantic, Some("b")),
        ];
        let mut emitted = 0;
        let error = project_records(
            schema::source_projection::SOURCE_AGY,
            Path::new("cycle.json"),
            records,
            |_| {
                emitted += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(emitted, 0);
        assert!(error.to_string().contains("cycle"));
    }

    #[test]
    fn shared_canonical_json_sorts_objects_and_keeps_last_duplicate() {
        let raw = Bytes::from_source(br#"{ "b": [true, null], "a": 1, "a": 2 }"#.to_vec());
        assert_eq!(canonical_json(raw).unwrap(), r#"{"a":2,"b":[true,null]}"#);
        assert_eq!(
            canonical_json_string("quote: \"; slash: \\; line:\n"),
            r#""quote: \"; slash: \\; line:\n""#
        );
    }
}
