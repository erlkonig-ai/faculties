//! Canonical constructors for the Archive block DAG.
//!
//! Each constructor returns a self-contained [`Fragment`]. Child fragments
//! are spread into their parent, consuming the child's exports while retaining
//! all facts and blobs. The resulting root therefore follows the data model:
//!
//! ```text
//! content fact -> content part -> block -> source projection
//! ```
//!
//! Kind markers and source annotations are attached only after intrinsic
//! construction. They remain queryable without becoming hidden inputs to a
//! content-derived id.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::Bytes;
use anyhow::{anyhow, bail, Result};
use triblespace::core::blob::encodings::succinctarchive::{OrderedUniverse, UnionArchive};
use triblespace::core::blob::MemoryBlobStoreSnapshot;
use triblespace::core::inline::IntoInline;
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::{BlobStoreGet, BlobStoreList, SnapshotSource};
use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval, U256BE};
use triblespace::prelude::*;

use crate::files;
use crate::schemas::{blockdag as schema, files as files_schema};

/// Source-occurrence evidence that must not affect the projected block or
/// projection-receipt identity.
///
/// Every field is additive. `None` means that the source supplied no usable
/// evidence; it never inserts a sentinel value.
#[derive(Clone, Debug, Default)]
pub struct ProjectionAnnotations {
    /// Source receipts that additively support the projected block's semantic
    /// predecessor classes. This is not exact vendor occurrence adjacency;
    /// that evidence remains in the exact raw record.
    pub semantic_predecessor_support: Vec<Id>,
    /// Genuine source timestamp claim, if independently decodable.
    pub source_timestamp: Option<Inline<NsTAIInterval>>,
    /// Stable Relations entity that produced this occurrence.
    pub author: Option<Id>,
    /// Stable Relations entity whose stream observed or produced it.
    pub experiencer: Option<Id>,
    /// Exact source spelling of the author field.
    pub raw_author: Option<String>,
    /// Exact source spelling of the role field.
    pub raw_role: Option<String>,
    /// Exact source spelling of the model field.
    pub raw_model: Option<String>,
    /// Movable source path. This reuses Files' occurrence-level attribute.
    pub source_path: Option<String>,
}

type TextHandle = Inline<Handle<UTF8String>>;
type RawHandle = Inline<Handle<RawBytes>>;
type IntervalValue = Inline<NsTAIInterval>;
type OrdinalValue = Inline<U256BE>;
type OverlayReader = MemoryBlobStoreSnapshot;

/// Result of validating one exact materialized Archive catalog.
///
/// `Pending` is deliberately limited to attachment residency: every asserted
/// handle already fixes the missing bytes, so those bytes may arrive without
/// changing the catalog's denotation. Missing graph entities and malformed
/// facts are [`Rejected`](Self::Rejected), because repairing them requires a
/// different set of tribles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogValidation {
    /// Structure, intrinsic identities, closure, and attachment residency are
    /// canonical. Durable payload hashes and decodings remain lazy until the
    /// bytes are consumed; newly staged payloads are validated before publish.
    Accepted,
    /// The graph is canonical, but these content hashes are not resident yet.
    Pending { missing: BTreeSet<[u8; 32]> },
    /// A deterministic structural, hashing, or attachment-format violation.
    Rejected(String),
}

impl CatalogValidation {
    /// True only for a fully resident, canonical catalog.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Default)]
struct AttachmentPlan {
    texts: BTreeSet<TextHandle>,
    raws: BTreeSet<RawHandle>,
    media_type_names: BTreeSet<TextHandle>,
    source_chunks: BTreeMap<Id, (u128, RawHandle)>,
    source_snapshots: Vec<SourceSnapshotPlan>,
}

struct SourceSnapshotPlan {
    id: Id,
    byte_length: u128,
    chunks: Vec<Id>,
}

fn rooted(fragment: &Fragment, what: &str) -> Result<Id> {
    fragment
        .root()
        .ok_or_else(|| anyhow!("{what} must export exactly one root"))
}

fn attach_kind(mut fragment: Fragment, kind: Id, what: &str) -> Result<Fragment> {
    let root = rooted(&fragment, what)?;
    fragment += entity! { ExclusiveId::force_ref(&root) @ metadata::tag: &kind };
    Ok(fragment)
}

/// Queryable names for the reified Archive modality and direction tags.
///
/// These facts are ordinary collection data rather than renderer knowledge.
/// Repeating them in authored imports is harmless set duplication, and lets a
/// reader display a newly introduced tag without adding another match table.
pub fn vocabulary_fragment() -> Fragment {
    let mut fragment = Fragment::empty();
    for &(id, name) in schema::content_fact::modality::SPECS
        .iter()
        .chain(schema::content_fact::direction::SPECS)
    {
        let name = fragment.put::<UTF8String, _>(name.to_owned());
        fragment += entity! { ExclusiveId::force_ref(&id) @
            metadata::tag: &metadata::KIND_TAG,
            metadata::name: name,
        };
    }
    fragment
}

/// Construct one intrinsic byte range inside a frozen source snapshot.
pub fn source_chunk(offset: u128, bytes: Bytes) -> Result<Fragment> {
    let offset: Inline<U256BE> = offset.to_inline();
    let mut fragment = Fragment::empty();
    let bytes = fragment.put::<RawBytes, _>(bytes);
    fragment += entity! { _ @
        schema::source_chunk::offset: offset,
        schema::source_chunk::bytes: bytes,
    };
    attach_kind(fragment, schema::source_chunk::KIND, "source chunk")
}

/// Construct one exact frozen-source snapshot over intrinsic byte ranges.
///
/// `chunks` exports [`schema::source_chunk`] roots. Their offsets and byte
/// handles determine ordering and reconstruction; the snapshot's total length
/// makes validation independent of import history or collection COMMIT grouping.
pub fn source_snapshot(
    namespace: Id,
    locator: impl Into<String>,
    byte_length: u128,
    chunks: Fragment,
    source_path: Option<String>,
) -> Result<Fragment> {
    let byte_length: Inline<U256BE> = byte_length.to_inline();
    let mut fragment = Fragment::empty();
    let locator = fragment.put::<UTF8String, _>(locator.into());
    fragment += entity! { _ @
        schema::source_projection::source_namespace: &namespace,
        schema::source_projection::source_locator: locator,
        schema::source_snapshot::byte_length: byte_length,
        schema::source_snapshot::contains*: chunks,
    };
    let mut fragment = attach_kind(fragment, schema::source_snapshot::KIND, "source snapshot")?;
    if let Some(source_path) = source_path {
        let snapshot = rooted(&fragment, "source snapshot")?;
        let path = fragment.put::<UTF8String, _>(source_path);
        fragment += entity! { ExclusiveId::force_ref(&snapshot) @
            files_schema::file::source_path: path,
        };
    }
    Ok(fragment)
}

/// Construct one intrinsic textual content fact.
pub fn text_fact(modality: Id, direction: Id, text: impl Into<String>) -> Result<Fragment> {
    text_fact_blob(modality, direction, text.into())
}

/// Construct one intrinsic textual fact while retaining a source-backed view.
pub fn text_fact_view(modality: Id, direction: Id, text: anybytes::View<str>) -> Result<Fragment> {
    text_fact_blob(modality, direction, text)
}

fn text_fact_blob<T>(modality: Id, direction: Id, text: T) -> Result<Fragment>
where
    T: triblespace::core::blob::IntoBlob<UTF8String>,
{
    let mut fragment = Fragment::empty();
    let payload = fragment.put::<UTF8String, _>(text);
    fragment += entity! { _ @
        schema::content_fact::modality: &modality,
        schema::content_fact::direction: &direction,
        schema::content_fact::payload: payload,
    };
    attach_kind(fragment, schema::content_fact::KIND, "content fact")
}

/// Construct one intrinsic resident binary content fact.
///
/// The media type is normalized by Files and represented by the same
/// intrinsic media-type entity used by canonical file records.
pub fn blob_fact<T>(modality: Id, direction: Id, bytes: T, media_type: &str) -> Result<Fragment>
where
    T: triblespace::core::blob::IntoBlob<RawBytes>,
{
    let mut fragment = Fragment::empty();
    let blob = fragment.put::<RawBytes, _>(bytes);
    let media_type = files::media_type_fragment(media_type)?;
    fragment += entity! { _ @
        schema::content_fact::modality: &modality,
        schema::content_fact::direction: &direction,
        schema::content_fact::blob: blob,
        schema::content_fact::media_type*: media_type,
    };
    attach_kind(fragment, schema::content_fact::KIND, "content fact")
}

/// Construct one intrinsic unresolved external-asset fact.
///
/// A pointer is always scoped by its source namespace. Media type and claimed
/// byte size participate only when genuinely known.
pub fn asset_pointer_fact(
    modality: Id,
    direction: Id,
    asset_namespace: Id,
    pointer: impl Into<String>,
    media_type: Option<&str>,
    size: Option<u128>,
) -> Result<Fragment> {
    asset_pointer_fact_blob(
        modality,
        direction,
        asset_namespace,
        pointer.into(),
        media_type,
        size,
    )
}

/// Construct an unresolved asset fact from a source-backed pointer view.
pub fn asset_pointer_fact_view(
    modality: Id,
    direction: Id,
    asset_namespace: Id,
    pointer: anybytes::View<str>,
    media_type: Option<&str>,
    size: Option<u128>,
) -> Result<Fragment> {
    asset_pointer_fact_blob(
        modality,
        direction,
        asset_namespace,
        pointer,
        media_type,
        size,
    )
}

fn asset_pointer_fact_blob<P>(
    modality: Id,
    direction: Id,
    asset_namespace: Id,
    pointer: P,
    media_type: Option<&str>,
    size: Option<u128>,
) -> Result<Fragment>
where
    P: triblespace::core::blob::IntoBlob<UTF8String>,
{
    let mut fragment = Fragment::empty();
    let pointer = fragment.put::<UTF8String, _>(pointer);
    let media_type = media_type
        .map(files::media_type_fragment)
        .transpose()?
        .unwrap_or_else(Fragment::empty);
    fragment += entity! { _ @
        schema::content_fact::modality: &modality,
        schema::content_fact::direction: &direction,
        schema::content_fact::asset_namespace: &asset_namespace,
        schema::content_fact::asset_pointer: pointer,
        schema::content_fact::media_type*: media_type,
        schema::content_fact::asset_size?: size,
    };
    attach_kind(fragment, schema::content_fact::KIND, "content fact")
}

/// Add one recovered byte representation to a pointer-identified content fact.
///
/// The intrinsic fact root remains unchanged. Multiple distinct resolutions
/// are retained as explicit ambiguity for validation rather than resolved by
/// last-write-wins.
pub fn resolve_pointer_fact<T>(mut fact: Fragment, bytes: T) -> Result<Fragment>
where
    T: triblespace::core::blob::IntoBlob<RawBytes>,
{
    let root = rooted(&fact, "content fact")?;
    let resolved = fact.put::<RawBytes, _>(bytes);
    fact += entity! { ExclusiveId::force_ref(&root) @
        schema::content_fact::resolved_to: resolved,
    };
    Ok(fact)
}

/// Wrap one content fact in an ordinal-bearing intrinsic part.
///
/// `responds_to` is a semantic edge to another canonical part. Unresolved
/// vendor correlators stay on the raw source receipt instead.
pub fn content_part(ordinal: u64, fact: Fragment, responds_to: Option<Id>) -> Result<Fragment> {
    let fact_id = rooted(&fact, "content fact")?;
    let resolutions: BTreeSet<RawHandle> = find!(
        resolution: RawHandle,
        pattern!(&fact, [{ fact_id @ schema::content_fact::resolved_to: ?resolution }])
    )
    .collect();
    // A source occurrence carrying one exact recovered body selects it in the
    // part's identity. A genuinely unresolved or already-ambiguous fact makes
    // no such claim; ambiguity remains monotone evidence on the fact itself.
    let resolution =
        (resolutions.len() == 1).then(|| *resolutions.first().expect("one resolution exists"));
    let fragment = entity! { _ @
        schema::content_part::ordinal: ordinal,
        schema::content_part::fact*: fact,
        schema::content_part::responds_to?: responds_to,
        schema::content_part::resolution?: resolution,
    };
    attach_kind(fragment, schema::content_part::KIND, "content part")
}

/// Construct one intrinsic block from structural predecessors, an optional
/// genuine event interval, and zero or more exported content parts.
///
/// The unique predecessor-free, timeless, content-free block is the bottom
/// projection used by exact source receipts that yielded no semantic content.
pub fn block(
    predecessors: impl IntoIterator<Item = Id>,
    timestamp: Option<Inline<NsTAIInterval>>,
    parts: Fragment,
) -> Result<Fragment> {
    let predecessors: Vec<_> = predecessors.into_iter().collect();
    if parts.exports().next().is_none() && (!predecessors.is_empty() || timestamp.is_some()) {
        bail!("a content-free block must be the predecessor-free, timeless canonical bottom");
    }
    // IDENTITY IS `previous` + CONTENT. The timestamp is an ANNOTATION on that
    // identity, not part of it.
    //
    // It used to be in the core, for a good reason: first blocks have no
    // `previous`, so without a timestamp two conversations opening with the
    // same content collide at the root. But that assumed the timestamp is a
    // property of the EVENT. For Codex it is a property of WHEN THE FILE WAS
    // WRITTEN, and it changes on every reload.
    //
    // MEASURED 2026-09-01, two consecutive rollouts of one resumed session:
    // three byte-identical payloads, ZERO with the same timestamp — each
    // restamped to the replay moment (13:12:16.185Z -> 14:03:56.153Z), and two
    // events originally 1 ms apart collapsed onto the SAME new value, so the
    // original timing is destroyed rather than shifted. Identical text
    // therefore hashed to different blocks, and the replayed prefix was
    // re-stored: 872 KB of source added 1238 KB of pile. With ONE 2026-08
    // conversation carrying 622 rollouts, that is one conversation stored
    // several hundred times.
    //
    // Collapsing is also the TRUER statement. A replayed block is the same
    // block observed again; storing it 622 times asserts 622 distinct events.
    // Nothing is lost by collapsing, because multiplicity lives where it is
    // actually true: `source_projection` is identified by source locator and
    // raw record bytes and carries its own `source_timestamp`, so every
    // occurrence stays distinguishable and a query joining on time enumerates
    // them all. JP: "the timestamps unfold them."
    //
    // Root collisions become correct rather than hazardous: two conversations
    // that genuinely open with identical content DO share that opening, and
    // diverge at the first block that differs. This mirrors what Memory
    // already does — `observed_at` is a BTreeSet in `annotate_chunk`, never in
    // `chunk_core` ("genuine creation/import observations, outside intrinsic
    // state").
    let mut fragment = entity! { _ @
        schema::block::previous*: predecessors.iter(),
        schema::block::contains*: parts,
    };
    let root = rooted(&fragment, "block")?;
    fragment += entity! { ExclusiveId::force_ref(&root) @
        schema::block::timestamp?: timestamp,
    };
    debug_assert_eq!(fragment.root(), Some(root));
    attach_kind(fragment, schema::block::KIND, "block")
}

/// Construct one exact source-occurrence projection receipt.
///
/// The identity contains the source namespace, stable locator, exact raw
/// record bytes, and projected canonical block. Replaying the same record is
/// therefore naturally idempotent, while two source occurrences of one shared
/// block stay distinguishable.
pub fn source_projection<T>(
    source_namespace: Id,
    source_locator: impl Into<String>,
    raw_record: T,
    block: Fragment,
) -> Result<Fragment>
where
    T: triblespace::core::blob::IntoBlob<RawBytes>,
{
    source_projection_blob(source_namespace, source_locator.into(), raw_record, block)
}

/// Construct a source projection while retaining a source-backed locator view.
pub fn source_projection_view<T>(
    source_namespace: Id,
    source_locator: anybytes::View<str>,
    raw_record: T,
    block: Fragment,
) -> Result<Fragment>
where
    T: triblespace::core::blob::IntoBlob<RawBytes>,
{
    source_projection_blob(source_namespace, source_locator, raw_record, block)
}

fn source_projection_blob<L, T>(
    source_namespace: Id,
    source_locator: L,
    raw_record: T,
    block: Fragment,
) -> Result<Fragment>
where
    L: triblespace::core::blob::IntoBlob<UTF8String>,
    T: triblespace::core::blob::IntoBlob<RawBytes>,
{
    rooted(&block, "block")?;
    let mut fragment = Fragment::empty();
    let source_locator = fragment.put::<UTF8String, _>(source_locator);
    let raw_record = fragment.put::<RawBytes, _>(raw_record);
    fragment += entity! { _ @
        schema::source_projection::source_namespace: &source_namespace,
        schema::source_projection::source_locator: source_locator,
        schema::source_projection::raw_record: raw_record,
        schema::source_projection::projects_to*: block,
    };
    attach_kind(
        fragment,
        schema::source_projection::KIND,
        "source projection",
    )
}

/// Attach occurrence-scoped evidence without changing a projection receipt's
/// intrinsic root.
pub fn annotate_source_projection(
    mut projection: Fragment,
    annotations: ProjectionAnnotations,
) -> Result<Fragment> {
    let root = rooted(&projection, "source projection")?;
    let raw_author = annotations
        .raw_author
        .map(|value| projection.put::<UTF8String, _>(value));
    let raw_role = annotations
        .raw_role
        .map(|value| projection.put::<UTF8String, _>(value));
    let raw_model = annotations
        .raw_model
        .map(|value| projection.put::<UTF8String, _>(value));
    let source_path = annotations
        .source_path
        .map(|value| projection.put::<UTF8String, _>(value));

    projection += entity! { ExclusiveId::force_ref(&root) @
        schema::source_projection::semantic_predecessor_support*:
            annotations.semantic_predecessor_support.iter(),
        schema::source_projection::source_timestamp?: annotations.source_timestamp,
        schema::source_projection::author?: annotations.author,
        schema::source_projection::experiencer?: annotations.experiencer,
        schema::source_projection::raw_author?: raw_author.as_ref(),
        schema::source_projection::raw_role?: raw_role.as_ref(),
        schema::source_projection::raw_model?: raw_model.as_ref(),
        files_schema::file::source_path?: source_path.as_ref(),
    };
    debug_assert_eq!(projection.root(), Some(root));
    Ok(projection)
}

fn values_by_entity<T: Ord>(rows: impl IntoIterator<Item = (Id, T)>) -> BTreeMap<Id, BTreeSet<T>> {
    let mut values = BTreeMap::new();
    for (entity, value) in rows {
        values
            .entry(entity)
            .or_insert_with(BTreeSet::new)
            .insert(value);
    }
    values
}

fn values_for<T: Ord + Copy>(values: &BTreeMap<Id, BTreeSet<T>>, id: Id) -> BTreeSet<T> {
    values.get(&id).cloned().unwrap_or_default()
}

fn one_required<T: Ord + Copy>(
    values: &BTreeMap<Id, BTreeSet<T>>,
    id: Id,
    field: &str,
) -> Result<T> {
    let values = values_for(values, id);
    if values.len() != 1 {
        bail!(
            "entity {id:x} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(*values.first().expect("one value"))
}

fn one_optional<T: Ord + Copy>(
    values: &BTreeMap<Id, BTreeSet<T>>,
    id: Id,
    field: &str,
) -> Result<Option<T>> {
    let values = values_for(values, id);
    if values.len() > 1 {
        bail!(
            "entity {id:x} has {} values for optional scalar {field}",
            values.len()
        );
    }
    Ok(values.first().copied())
}

fn ids_of_kind<P>(facts: &P, kind: Id) -> BTreeSet<Id>
where
    P: TriblePattern,
{
    find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &kind }])
    )
    .collect()
}

fn ensure_intrinsic_with_kind(id: Id, core: Fragment, kind: Id, label: &str) -> Result<TribleSet> {
    let expected = core
        .root()
        .ok_or_else(|| anyhow!("{label} core has no unique intrinsic root"))?;
    if expected != id {
        bail!("{label} {id:x} does not match intrinsic root {expected:x}");
    }
    let mut facts = core.into_facts();
    facts += entity! { ExclusiveId::force_ref(&id) @ metadata::tag: &kind }.into_facts();
    Ok(facts)
}

fn known_modality(value: Id) -> bool {
    schema::content_fact::modality::SPECS
        .iter()
        .any(|(id, _)| *id == value)
}

fn textual_modality(value: Id) -> bool {
    [
        schema::content_fact::modality::TEXT,
        schema::content_fact::modality::TOOL_CALL,
        schema::content_fact::modality::TOOL_RESULT,
        schema::content_fact::modality::THINKING,
        schema::content_fact::modality::EVENT,
    ]
    .contains(&value)
}

fn media_modality(value: Id) -> bool {
    [
        schema::content_fact::modality::AUDIO,
        schema::content_fact::modality::IMAGE,
        schema::content_fact::modality::FILE,
        schema::content_fact::modality::VIDEO,
    ]
    .contains(&value)
}

fn known_direction(value: Id) -> bool {
    schema::content_fact::direction::SPECS
        .iter()
        .any(|(id, _)| *id == value)
}

fn require_disjoint(kinds: &[(&str, &BTreeSet<Id>)]) -> Result<()> {
    for (index, (left_name, left)) in kinds.iter().enumerate() {
        for (right_name, right) in &kinds[index + 1..] {
            if let Some(id) = left.intersection(right).next() {
                bail!("entity {id:x} is tagged as both {left_name} and {right_name}");
            }
        }
    }
    Ok(())
}

fn require_coverage(declared: &BTreeSet<Id>, referenced: &BTreeSet<Id>, label: &str) -> Result<()> {
    if let Some(id) = declared.difference(referenced).next() {
        bail!("orphan {label} {id:x} is not reachable from a source projection");
    }
    if let Some(id) = referenced.difference(declared).next() {
        bail!("reference names undeclared {label} {id:x}");
    }
    Ok(())
}

fn validate_dag(nodes: &BTreeMap<Id, BTreeSet<Id>>, label: &str) -> Result<()> {
    let mut remaining: BTreeMap<Id, usize> = nodes
        .iter()
        .map(|(node, predecessors)| (*node, predecessors.len()))
        .collect();
    let mut children = BTreeMap::<Id, Vec<Id>>::new();
    for (&node, predecessors) in nodes {
        for predecessor in predecessors {
            if !nodes.contains_key(predecessor) {
                bail!("{label} {node:x} cites missing predecessor {predecessor:x}");
            }
            children.entry(*predecessor).or_default().push(node);
        }
    }
    let mut ready: Vec<Id> = remaining
        .iter()
        .filter_map(|(node, count)| (*count == 0).then_some(*node))
        .collect();
    let mut visited = 0usize;
    while let Some(node) = ready.pop() {
        visited += 1;
        for child in children.get(&node).into_iter().flatten() {
            let count = remaining
                .get_mut(child)
                .expect("every child belongs to the graph");
            *count -= 1;
            if *count == 0 {
                ready.push(*child);
            }
        }
    }
    if visited != nodes.len() {
        bail!("{label} contains a predecessor cycle");
    }
    Ok(())
}

/// Prove the universal block-DAG denotation without reading any attachment.
///
/// The proof reconstructs every intrinsic id, enforces scalar cardinality and
/// graph closure, and then compares the reconstructed ontology with the input
/// exactly. Vendor parsing, source-locator grammar, role mapping, MIME
/// inference, and raw-record-to-projection equivalence intentionally remain
/// outside this universal layer.
fn validate_structure_with_rows<P>(
    facts: &P,
    observed: impl IntoIterator<Item = Trible>,
) -> Result<AttachmentPlan>
where
    P: TriblePattern,
{
    let content_facts = ids_of_kind(facts, schema::content_fact::KIND);
    let content_parts = ids_of_kind(facts, schema::content_part::KIND);
    let blocks = ids_of_kind(facts, schema::block::KIND);
    let projections = ids_of_kind(facts, schema::source_projection::KIND);
    let source_chunks = ids_of_kind(facts, schema::source_chunk::KIND);
    let source_snapshots = ids_of_kind(facts, schema::source_snapshot::KIND);
    let media_types = ids_of_kind(facts, files_schema::KIND_MEDIA_TYPE);
    require_disjoint(&[
        ("content fact", &content_facts),
        ("content part", &content_parts),
        ("block", &blocks),
        ("source projection", &projections),
        ("source chunk", &source_chunks),
        ("source snapshot", &source_snapshots),
        ("media type", &media_types),
    ])?;

    let media_names = values_by_entity(find!(
        (entity: Id, value: TextHandle),
        pattern!(facts, [{ ?entity @ metadata::name: ?value }])
    ));
    let vocabulary_ids: BTreeSet<_> = schema::content_fact::modality::SPECS
        .iter()
        .chain(schema::content_fact::direction::SPECS)
        .map(|(id, _)| *id)
        .collect();
    let has_vocabulary = vocabulary_ids.iter().any(|id| media_names.contains_key(id));
    let modalities = values_by_entity(find!(
        (entity: Id, value: Id),
        pattern!(facts, [{ ?entity @ schema::content_fact::modality: ?value }])
    ));
    let directions = values_by_entity(find!(
        (entity: Id, value: Id),
        pattern!(facts, [{ ?entity @ schema::content_fact::direction: ?value }])
    ));
    let payloads = values_by_entity(find!(
        (entity: Id, value: TextHandle),
        pattern!(facts, [{ ?entity @ schema::content_fact::payload: ?value }])
    ));
    let blobs = values_by_entity(find!(
        (entity: Id, value: RawHandle),
        pattern!(facts, [{ ?entity @ schema::content_fact::blob: ?value }])
    ));
    let asset_pointers = values_by_entity(find!(
        (entity: Id, value: TextHandle),
        pattern!(facts, [{ ?entity @ schema::content_fact::asset_pointer: ?value }])
    ));
    let asset_namespaces = values_by_entity(find!(
        (entity: Id, value: Id),
        pattern!(facts, [{ ?entity @ schema::content_fact::asset_namespace: ?value }])
    ));
    let fact_media_types = values_by_entity(find!(
        (entity: Id, value: Id),
        pattern!(facts, [{ ?entity @ schema::content_fact::media_type: ?value }])
    ));
    let asset_sizes = values_by_entity(find!(
        (entity: Id, value: OrdinalValue),
        pattern!(facts, [{ ?entity @ schema::content_fact::asset_size: ?value }])
    ));
    let resolutions = values_by_entity(find!(
        (entity: Id, value: RawHandle),
        pattern!(facts, [{ ?entity @ schema::content_fact::resolved_to: ?value }])
    ));
    let source_chunk_offsets = values_by_entity(find!(
        (entity: Id, value: OrdinalValue),
        pattern!(facts, [{ ?entity @ schema::source_chunk::offset: ?value }])
    ));
    let source_chunk_bytes = values_by_entity(find!(
        (entity: Id, value: RawHandle),
        pattern!(facts, [{ ?entity @ schema::source_chunk::bytes: ?value }])
    ));
    let source_snapshot_lengths = values_by_entity(find!(
        (entity: Id, value: OrdinalValue),
        pattern!(facts, [{ ?entity @ schema::source_snapshot::byte_length: ?value }])
    ));
    let source_snapshot_chunks = values_by_entity(find!(
        (entity: Id, value: Id),
        pattern!(facts, [{ ?entity @ schema::source_snapshot::contains: ?value }])
    ));

    let ordinals = values_by_entity(find!(
        (entity: Id, value: OrdinalValue),
        pattern!(facts, [{ ?entity @ schema::content_part::ordinal: ?value }])
    ));
    let part_facts = values_by_entity(find!(
        (entity: Id, value: Id),
        pattern!(facts, [{ ?entity @ schema::content_part::fact: ?value }])
    ));
    let responds_to = values_by_entity(find!(
        (entity: Id, value: Id),
        pattern!(facts, [{ ?entity @ schema::content_part::responds_to: ?value }])
    ));
    let part_resolutions = values_by_entity(find!(
        (entity: Id, value: RawHandle),
        pattern!(facts, [{ ?entity @ schema::content_part::resolution: ?value }])
    ));

    let block_previous = values_by_entity(find!(
        (entity: Id, value: Id),
        pattern!(facts, [{ ?entity @ schema::block::previous: ?value }])
    ));
    let block_timestamps = values_by_entity(find!(
        (entity: Id, value: IntervalValue),
        pattern!(facts, [{ ?entity @ schema::block::timestamp: ?value }])
    ));
    let block_parts = values_by_entity(find!(
        (entity: Id, value: Id),
        pattern!(facts, [{ ?entity @ schema::block::contains: ?value }])
    ));

    let source_namespaces = values_by_entity(find!(
        (entity: Id, value: Id),
        pattern!(facts, [{ ?entity @ schema::source_projection::source_namespace: ?value }])
    ));
    let source_locators = values_by_entity(find!(
        (entity: Id, value: TextHandle),
        pattern!(facts, [{ ?entity @ schema::source_projection::source_locator: ?value }])
    ));
    let raw_records = values_by_entity(find!(
        (entity: Id, value: RawHandle),
        pattern!(facts, [{ ?entity @ schema::source_projection::raw_record: ?value }])
    ));
    let projected_blocks = values_by_entity(find!(
        (entity: Id, value: Id),
        pattern!(facts, [{ ?entity @ schema::source_projection::projects_to: ?value }])
    ));
    let semantic_predecessor_support = values_by_entity(find!(
        (entity: Id, value: Id),
        pattern!(facts, [{
            ?entity @ schema::source_projection::semantic_predecessor_support: ?value
        }])
    ));
    let source_timestamps = values_by_entity(find!(
        (entity: Id, value: IntervalValue),
        pattern!(facts, [{ ?entity @ schema::source_projection::source_timestamp: ?value }])
    ));
    let authors = values_by_entity(find!(
        (entity: Id, value: Id),
        pattern!(facts, [{ ?entity @ schema::source_projection::author: ?value }])
    ));
    let experiencers = values_by_entity(find!(
        (entity: Id, value: Id),
        pattern!(facts, [{ ?entity @ schema::source_projection::experiencer: ?value }])
    ));
    let raw_authors = values_by_entity(find!(
        (entity: Id, value: TextHandle),
        pattern!(facts, [{ ?entity @ schema::source_projection::raw_author: ?value }])
    ));
    let raw_roles = values_by_entity(find!(
        (entity: Id, value: TextHandle),
        pattern!(facts, [{ ?entity @ schema::source_projection::raw_role: ?value }])
    ));
    let raw_models = values_by_entity(find!(
        (entity: Id, value: TextHandle),
        pattern!(facts, [{ ?entity @ schema::source_projection::raw_model: ?value }])
    ));
    let source_paths = values_by_entity(find!(
        (entity: Id, value: TextHandle),
        pattern!(facts, [{ ?entity @ files_schema::file::source_path: ?value }])
    ));

    let mut expected = TribleSet::new();
    let mut attachments = AttachmentPlan::default();
    let mut referenced_media_types = BTreeSet::new();
    for id in &media_types {
        let name = one_required(&media_names, *id, "media type name")?;
        let core = entity! {
            metadata::tag: &files_schema::KIND_MEDIA_TYPE,
            metadata::name: name,
        };
        let expected_id = core.root().expect("media type core has one root");
        if expected_id != *id {
            bail!("media type {id:x} does not match intrinsic root {expected_id:x}");
        }
        expected += core.into_facts();
        attachments.texts.insert(name);
        attachments.media_type_names.insert(name);
    }

    // Once vocabulary annotation is present, require the complete canonical
    // bootstrap vocabulary. Additional names are ordinary additive graph data:
    // readers may display all of them without a last-writer-wins label table.
    // A completely absent vocabulary remains valid so the writer can add the
    // bootstrap monotonically to a pre-vocabulary collection.
    if has_vocabulary {
        for id in &vocabulary_ids {
            let names = values_for(&media_names, *id);
            if names.is_empty() {
                bail!("entity {id:x} has no Archive vocabulary name");
            }
            attachments.texts.extend(names.iter().copied());
            expected += entity! { ExclusiveId::force_ref(id) @
                metadata::name*: names.iter(),
            }
            .into_facts();
        }
        expected += vocabulary_fragment().into_facts();
    }

    let mut referenced_source_chunks = BTreeSet::new();
    for id in &source_chunks {
        let offset = one_required(&source_chunk_offsets, *id, "source chunk offset")?;
        let offset_number = u128::try_from_inline(&offset)
            .map_err(|error| anyhow!("source chunk {id:x} offset does not fit u128: {error:?}"))?;
        let bytes = one_required(&source_chunk_bytes, *id, "source chunk bytes")?;
        let core = entity! { _ @
            schema::source_chunk::offset: offset,
            schema::source_chunk::bytes: bytes,
        };
        expected +=
            ensure_intrinsic_with_kind(*id, core, schema::source_chunk::KIND, "source chunk")?;
        attachments
            .source_chunks
            .insert(*id, (offset_number, bytes));
    }

    for id in &source_snapshots {
        let namespace = one_required(&source_namespaces, *id, "source snapshot namespace")?;
        let locator = one_required(&source_locators, *id, "source snapshot locator")?;
        let byte_length =
            one_required(&source_snapshot_lengths, *id, "source snapshot byte length")?;
        let byte_length_number = u128::try_from_inline(&byte_length).map_err(|error| {
            anyhow!("source snapshot {id:x} length does not fit u128: {error:?}")
        })?;
        let chunks = values_for(&source_snapshot_chunks, *id);
        for chunk in &chunks {
            if !source_chunks.contains(chunk) {
                bail!("source snapshot {id:x} cites missing chunk {chunk:x}");
            }
        }
        referenced_source_chunks.extend(chunks.iter().copied());
        let paths = values_for(&source_paths, *id);
        let core = entity! { _ @
            schema::source_projection::source_namespace: &namespace,
            schema::source_projection::source_locator: locator,
            schema::source_snapshot::byte_length: byte_length,
            schema::source_snapshot::contains*: chunks.iter(),
        };
        let mut canonical = ensure_intrinsic_with_kind(
            *id,
            core,
            schema::source_snapshot::KIND,
            "source snapshot",
        )?;
        canonical += entity! { ExclusiveId::force_ref(id) @
            files_schema::file::source_path*: paths.iter(),
        }
        .into_facts();
        expected += canonical;
        attachments.texts.insert(locator);
        attachments.texts.extend(paths.iter().copied());
        attachments.source_snapshots.push(SourceSnapshotPlan {
            id: *id,
            byte_length: byte_length_number,
            chunks: chunks.into_iter().collect(),
        });
    }
    require_coverage(&source_chunks, &referenced_source_chunks, "source chunk")?;

    for id in &content_facts {
        let modality = one_required(&modalities, *id, "content fact modality")?;
        if !known_modality(modality) {
            bail!("content fact {id:x} has unknown modality {modality:x}");
        }
        let direction = one_required(&directions, *id, "content fact direction")?;
        if !known_direction(direction) {
            bail!("content fact {id:x} has unknown direction {direction:x}");
        }
        let payload = one_optional(&payloads, *id, "content fact payload")?;
        let blob = one_optional(&blobs, *id, "content fact blob")?;
        let pointer = one_optional(&asset_pointers, *id, "content fact asset pointer")?;
        let namespace = one_optional(&asset_namespaces, *id, "content fact asset namespace")?;
        let media_type = one_optional(&fact_media_types, *id, "content fact media type")?;
        let size = one_optional(&asset_sizes, *id, "content fact asset size")?;
        if let Some(size) = size {
            let _: u128 = size.try_from_inline().map_err(|error| {
                anyhow!("content fact {id:x} asset size does not fit u128: {error:?}")
            })?;
        }
        let resolved = values_for(&resolutions, *id);

        let core = match (payload, blob, pointer) {
            (Some(payload), None, None) => {
                if !textual_modality(modality) {
                    bail!("content fact {id:x} uses a text payload with a media modality");
                }
                if namespace.is_some()
                    || media_type.is_some()
                    || size.is_some()
                    || !resolved.is_empty()
                {
                    bail!("text content fact {id:x} carries media-only fields");
                }
                attachments.texts.insert(payload);
                entity! { _ @
                    schema::content_fact::modality: &modality,
                    schema::content_fact::direction: &direction,
                    schema::content_fact::payload: payload,
                }
            }
            (None, Some(blob), None) => {
                if !media_modality(modality) {
                    bail!("content fact {id:x} uses resident bytes with a textual modality");
                }
                if namespace.is_some() || size.is_some() || !resolved.is_empty() {
                    bail!("resident content fact {id:x} carries pointer-only fields");
                }
                let media_type = media_type.ok_or_else(|| {
                    anyhow!("resident content fact {id:x} has no canonical media type")
                })?;
                if !media_types.contains(&media_type) {
                    bail!("content fact {id:x} cites missing media type {media_type:x}");
                }
                referenced_media_types.insert(media_type);
                attachments.raws.insert(blob);
                entity! { _ @
                    schema::content_fact::modality: &modality,
                    schema::content_fact::direction: &direction,
                    schema::content_fact::blob: blob,
                    schema::content_fact::media_type: &media_type,
                }
            }
            (None, None, Some(pointer)) => {
                if !media_modality(modality) {
                    bail!("content fact {id:x} uses an asset pointer with a textual modality");
                }
                let namespace = namespace
                    .ok_or_else(|| anyhow!("pointer content fact {id:x} has no asset namespace"))?;
                if let Some(media_type) = media_type {
                    if !media_types.contains(&media_type) {
                        bail!("content fact {id:x} cites missing media type {media_type:x}");
                    }
                    referenced_media_types.insert(media_type);
                }
                attachments.texts.insert(pointer);
                attachments.raws.extend(resolved.iter().copied());
                entity! { _ @
                    schema::content_fact::modality: &modality,
                    schema::content_fact::direction: &direction,
                    schema::content_fact::asset_pointer: pointer,
                    schema::content_fact::asset_namespace: &namespace,
                    schema::content_fact::media_type?: media_type,
                    schema::content_fact::asset_size?: size,
                }
            }
            _ => bail!(
                "content fact {id:x} must have exactly one of payload, blob, or asset pointer"
            ),
        };
        let mut canonical =
            ensure_intrinsic_with_kind(*id, core, schema::content_fact::KIND, "content fact")?;
        canonical += entity! { ExclusiveId::force_ref(id) @
            schema::content_fact::resolved_to*: resolved.iter(),
        }
        .into_facts();
        expected += canonical;
    }

    let mut ordinal_numbers = BTreeMap::new();
    let mut referenced_content_facts = BTreeSet::new();
    for id in &content_parts {
        let ordinal = one_required(&ordinals, *id, "content part ordinal")?;
        let ordinal_number: u64 = ordinal
            .try_from_inline()
            .map_err(|error| anyhow!("content part {id:x} ordinal does not fit u64: {error:?}"))?;
        let fact = one_required(&part_facts, *id, "content part fact")?;
        if !content_facts.contains(&fact) {
            bail!("content part {id:x} cites missing content fact {fact:x}");
        }
        referenced_content_facts.insert(fact);
        let response = one_optional(&responds_to, *id, "content part responds-to")?;
        if let Some(response) = response {
            if !content_parts.contains(&response) {
                bail!("content part {id:x} responds to missing part {response:x}");
            }
        }
        let resolution = one_optional(&part_resolutions, *id, "content part resolution")?;
        if let Some(resolution) = resolution {
            let available = values_for(&resolutions, fact);
            if !available.contains(&resolution) {
                bail!("content part {id:x} selects resolution absent from content fact {fact:x}");
            }
        }
        let core = entity! { _ @
            schema::content_part::ordinal: ordinal,
            schema::content_part::fact: &fact,
            schema::content_part::responds_to?: response,
            schema::content_part::resolution?: resolution,
        };
        expected +=
            ensure_intrinsic_with_kind(*id, core, schema::content_part::KIND, "content part")?;
        ordinal_numbers.insert(*id, ordinal_number);
    }

    let mut block_graph = BTreeMap::new();
    let mut referenced_parts = BTreeSet::new();
    for id in &blocks {
        let previous = values_for(&block_previous, *id);
        for predecessor in &previous {
            if !blocks.contains(predecessor) {
                bail!("block {id:x} cites missing predecessor {predecessor:x}");
            }
        }
        let timestamps = values_for(&block_timestamps, *id);
        for timestamp in &timestamps {
            let _: (i128, i128) = timestamp.try_from_inline().map_err(|error| {
                anyhow!("block {id:x} has invalid timestamp interval: {error:?}")
            })?;
        }
        let parts = values_for(&block_parts, *id);
        if parts.is_empty() && (!previous.is_empty() || !timestamps.is_empty()) {
            bail!(
                "content-free block {id:x} is not the predecessor-free, timeless canonical bottom"
            );
        }
        let mut by_ordinal = BTreeMap::new();
        for part in &parts {
            if !content_parts.contains(part) {
                bail!("block {id:x} contains missing part {part:x}");
            }
            let ordinal = ordinal_numbers[part];
            if let Some(other) = by_ordinal.insert(ordinal, *part) {
                bail!("block {id:x} contains parts {other:x} and {part:x} at ordinal {ordinal}");
            }
        }
        for (expected_ordinal, actual) in (0u64..).zip(by_ordinal.keys().copied()) {
            if actual != expected_ordinal {
                bail!(
                    "block {id:x} has non-contiguous part ordinals; expected {expected_ordinal}, found {actual}"
                );
            }
        }
        referenced_parts.extend(parts.iter().copied());
        let core = entity! { _ @
            schema::block::previous*: previous.iter(),
            schema::block::contains*: parts.iter(),
        };
        let mut canonical = ensure_intrinsic_with_kind(*id, core, schema::block::KIND, "block")?;
        canonical += entity! { ExclusiveId::force_ref(id) @
            schema::block::timestamp*: timestamps.iter(),
        }
        .into_facts();
        expected += canonical;
        block_graph.insert(*id, previous);
    }
    validate_dag(&block_graph, "block DAG")?;

    let mut referenced_blocks = BTreeSet::new();
    for id in &projections {
        let namespace = one_required(&source_namespaces, *id, "source projection namespace")?;
        let locator = one_required(&source_locators, *id, "source projection locator")?;
        let raw_record = one_required(&raw_records, *id, "source projection raw record")?;
        let projected = one_required(&projected_blocks, *id, "source projection target block")?;
        if !blocks.contains(&projected) {
            bail!("source projection {id:x} cites missing block {projected:x}");
        }
        referenced_blocks.insert(projected);
        let predecessor_support = values_for(&semantic_predecessor_support, *id);
        let direct_predecessors = block_graph
            .get(&projected)
            .expect("every projected block has a validated predecessor set");
        for receipt in &predecessor_support {
            if !projections.contains(receipt) {
                bail!(
                    "source projection {id:x} cites missing semantic-support receipt {receipt:x}"
                );
            }
            let supporting_block = one_required(
                &projected_blocks,
                *receipt,
                "semantic-support receipt target block",
            )?;
            if !direct_predecessors.contains(&supporting_block) {
                bail!(
                    "source projection {id:x} cites receipt {receipt:x} for unrelated block {supporting_block:x}"
                );
            }
        }
        let source_timestamp =
            one_optional(&source_timestamps, *id, "source projection timestamp")?;
        if let Some(timestamp) = source_timestamp {
            let _: (i128, i128) = timestamp.try_from_inline().map_err(|error| {
                anyhow!("source projection {id:x} has invalid timestamp: {error:?}")
            })?;
        }
        let author = one_optional(&authors, *id, "source projection author")?;
        let experiencer = one_optional(&experiencers, *id, "source projection experiencer")?;
        let raw_author = one_optional(&raw_authors, *id, "source projection raw author")?;
        let raw_role = one_optional(&raw_roles, *id, "source projection raw role")?;
        let raw_model = one_optional(&raw_models, *id, "source projection raw model")?;
        let paths = values_for(&source_paths, *id);

        attachments.texts.insert(locator);
        attachments.raws.insert(raw_record);
        attachments.texts.extend(raw_author);
        attachments.texts.extend(raw_role);
        attachments.texts.extend(raw_model);
        attachments.texts.extend(paths.iter().copied());

        let core = entity! { _ @
            schema::source_projection::source_namespace: &namespace,
            schema::source_projection::source_locator: locator,
            schema::source_projection::raw_record: raw_record,
            schema::source_projection::projects_to: &projected,
        };
        let mut canonical = ensure_intrinsic_with_kind(
            *id,
            core,
            schema::source_projection::KIND,
            "source projection",
        )?;
        canonical += entity! { ExclusiveId::force_ref(id) @
            schema::source_projection::semantic_predecessor_support*:
                predecessor_support.iter(),
            schema::source_projection::source_timestamp?: source_timestamp,
            schema::source_projection::author?: author,
            schema::source_projection::experiencer?: experiencer,
            schema::source_projection::raw_author?: raw_author,
            schema::source_projection::raw_role?: raw_role,
            schema::source_projection::raw_model?: raw_model,
            files_schema::file::source_path*: paths.iter(),
        }
        .into_facts();
        expected += canonical;
    }

    require_coverage(&media_types, &referenced_media_types, "media type")?;
    require_coverage(&content_facts, &referenced_content_facts, "content fact")?;
    require_coverage(&content_parts, &referenced_parts, "content part")?;
    require_coverage(&blocks, &referenced_blocks, "block")?;

    let (missing, unexpected) = canonical_difference_counts(&expected, observed);
    if missing != 0 || unexpected != 0 {
        bail!(
            "block-DAG catalog is not an exact canonical ontology ({missing} missing, {unexpected} unexpected facts)"
        );
    }
    Ok(attachments)
}

fn canonical_difference_counts(
    expected: &TribleSet,
    observed: impl IntoIterator<Item = Trible>,
) -> (usize, usize) {
    let mut expected = expected.iter_ordered().copied().peekable();
    let mut observed = observed.into_iter().peekable();
    let mut missing = 0usize;
    let mut unexpected = 0usize;
    loop {
        match (expected.peek(), observed.peek()) {
            (Some(left), Some(right)) => match left.cmp(right) {
                std::cmp::Ordering::Less => {
                    missing += 1;
                    expected.next();
                }
                std::cmp::Ordering::Equal => {
                    expected.next();
                    observed.next();
                }
                std::cmp::Ordering::Greater => {
                    unexpected += 1;
                    observed.next();
                }
            },
            (Some(_), None) => {
                missing += expected.count();
                break;
            }
            (None, Some(_)) => {
                unexpected += observed.count();
                break;
            }
            (None, None) => break,
        }
    }
    (missing, unexpected)
}

fn validate_structure(facts: &TribleSet) -> Result<AttachmentPlan> {
    validate_structure_with_rows(facts, facts.iter_ordered().copied())
}

fn validate_succinct_structure(facts: &UnionArchive<OrderedUniverse>) -> Result<AttachmentPlan> {
    validate_structure_with_rows(facts, facts.iter())
}

/// Validate only the canonical graph, without consulting any blob store.
///
/// This proves intrinsic identities, exact field shapes, graph closure,
/// predecessor acyclicity, ordinal continuity, and reachability coverage. It
/// deliberately does not claim that named attachments are resident or
/// decodable; use [`validate_catalog`] or [`validate_catalog_union`] for that.
pub fn validate_catalog_structure(facts: &TribleSet) -> Result<()> {
    validate_structure(facts).map(drop)
}

fn read_text_attachment(
    reader: &PileSnapshot,
    overlay: Option<&OverlayReader>,
    handle: TextHandle,
) -> std::result::Result<Option<String>, String> {
    if let Some(overlay) = overlay {
        if overlay
            .contains_blob(handle)
            .map_err(|error| format!("inspect staged UTF8String attachment: {error}"))?
        {
            let value: anybytes::View<str> = overlay.get(handle).map_err(|error| {
                format!(
                    "invalid staged UTF8String attachment {}: {error}",
                    hex::encode(handle.raw)
                )
            })?;
            return Ok(Some(value.to_string()));
        }
    }
    if !reader
        .contains_blob(handle)
        .map_err(|error| format!("inspect resident UTF8String attachment: {error}"))?
    {
        return Ok(None);
    }
    let value: anybytes::View<str> = reader.get(handle).map_err(|error| {
        format!(
            "invalid resident UTF8String attachment {}: {error}",
            hex::encode(handle.raw)
        )
    })?;
    Ok(Some(value.to_string()))
}

fn text_attachment_present(
    reader: &PileSnapshot,
    overlay: Option<&OverlayReader>,
    handle: TextHandle,
) -> std::result::Result<bool, String> {
    if let Some(overlay) = overlay {
        if overlay
            .contains_blob(handle)
            .map_err(|error| format!("inspect staged UTF8String attachment: {error}"))?
        {
            let _: anybytes::View<str> = overlay.get(handle).map_err(|error| {
                format!(
                    "invalid staged UTF8String attachment {}: {error}",
                    hex::encode(handle.raw)
                )
            })?;
            return Ok(true);
        }
    }
    reader
        .contains_blob(handle)
        .map_err(|error| format!("inspect resident UTF8String attachment: {error}"))
}

fn raw_attachment_present(
    reader: &PileSnapshot,
    overlay: Option<&OverlayReader>,
    handle: RawHandle,
) -> std::result::Result<bool, String> {
    if let Some(overlay) = overlay {
        if overlay
            .contains_blob(handle)
            .map_err(|error| format!("inspect staged RawBytes attachment: {error}"))?
        {
            let _: Bytes = overlay.get(handle).map_err(|error| {
                format!(
                    "invalid staged RawBytes attachment {}: {error}",
                    hex::encode(handle.raw)
                )
            })?;
            return Ok(true);
        }
    }
    reader
        .contains_blob(handle)
        .map_err(|error| format!("inspect resident RawBytes attachment: {error}"))
}

fn validate_source_snapshots(
    chunks: &BTreeMap<Id, (u128, RawHandle)>,
    snapshots: &[SourceSnapshotPlan],
    stored_lengths: &BTreeMap<RawHandle, u128>,
) -> std::result::Result<(), String> {
    for snapshot in snapshots {
        let mut ordered = snapshot
            .chunks
            .iter()
            .map(|chunk| {
                let (offset, handle) = chunks.get(chunk).ok_or_else(|| {
                    format!(
                        "source snapshot {:x} lost declared chunk {:x}",
                        snapshot.id, chunk
                    )
                })?;
                Ok((*offset, *chunk, *handle))
            })
            .collect::<std::result::Result<Vec<_>, String>>()?;
        ordered.sort_unstable();

        if snapshot.byte_length == 0 && !ordered.is_empty() {
            return Err(format!(
                "empty source snapshot {:x} contains byte chunks",
                snapshot.id
            ));
        }
        if snapshot.byte_length != 0 && ordered.is_empty() {
            return Err(format!(
                "nonempty source snapshot {:x} contains no byte chunks",
                snapshot.id
            ));
        }

        let mut cursor = 0u128;
        for (index, (offset, chunk, handle)) in ordered.iter().copied().enumerate() {
            if offset != cursor {
                return Err(format!(
                    "source snapshot {:x} chunk {:x} starts at {offset}, expected {cursor}",
                    snapshot.id, chunk
                ));
            }
            let is_last = index + 1 == ordered.len();
            let len = if is_last {
                snapshot.byte_length.checked_sub(offset).ok_or_else(|| {
                    format!(
                        "source snapshot {:x} chunk {:x} starts beyond its claimed length",
                        snapshot.id, chunk
                    )
                })?
            } else {
                schema::source_chunk::CANONICAL_BYTES as u128
            };
            if len == 0 || len > schema::source_chunk::CANONICAL_BYTES as u128 {
                return Err(format!(
                    "source snapshot {:x} chunk {:x} has noncanonical length {len}",
                    snapshot.id, chunk
                ));
            }
            if let Some(stored) = stored_lengths.get(&handle) {
                if *stored != len {
                    return Err(format!(
                        "source snapshot {:x} chunk {:x} stores {stored} bytes, expected {len}",
                        snapshot.id, chunk
                    ));
                }
            }
            if !is_last && len != schema::source_chunk::CANONICAL_BYTES as u128 {
                return Err(format!(
                    "source snapshot {:x} nonfinal chunk {:x} has length {len}, expected {}",
                    snapshot.id,
                    chunk,
                    schema::source_chunk::CANONICAL_BYTES
                ));
            }
            cursor = cursor.checked_add(len).ok_or_else(|| {
                format!("source snapshot {:x} length overflows u128", snapshot.id)
            })?;
        }
        if cursor != snapshot.byte_length {
            return Err(format!(
                "source snapshot {:x} reconstructs {cursor} bytes, claims {}",
                snapshot.id, snapshot.byte_length
            ));
        }
    }
    Ok(())
}

fn source_chunk_storage_lengths(
    reader: &PileSnapshot,
    overlay: Option<&OverlayReader>,
    chunks: &BTreeMap<Id, (u128, RawHandle)>,
) -> std::result::Result<BTreeMap<RawHandle, u128>, String> {
    let wanted: BTreeSet<_> = chunks.values().map(|(_, handle)| handle.raw).collect();
    let mut lengths = BTreeMap::new();
    if wanted.is_empty() {
        return Ok(lengths);
    }
    for raw in &wanted {
        let handle = Inline::<Handle<RawBytes>>::new(*raw);
        if let Some(info) = reader
            .blob_info(handle)
            .map_err(|error| format!("inspect resident source chunk: {error}"))?
        {
            lengths.insert(handle, u128::from(info.length));
        }
    }
    if let Some(overlay) = overlay {
        for info in overlay.blobs() {
            let info = info.map_err(|error| format!("enumerate staged source chunks: {error}"))?;
            if wanted.contains(&info.handle.raw) {
                let handle = Inline::<Handle<RawBytes>>::new(info.handle.raw);
                // A caller-supplied overlay can contain a forged handle.
                // Validate staged bytes once; durable Pile headers are trusted
                // only for length/presence and remain hash-lazy until read.
                let bytes: Bytes = overlay.get(handle).map_err(|error| {
                    format!(
                        "invalid staged source chunk {}: {error}",
                        hex::encode(handle.raw)
                    )
                })?;
                if bytes.len() as u64 != info.length {
                    return Err(format!(
                        "staged source chunk {} header length disagrees with its bytes",
                        hex::encode(handle.raw)
                    ));
                }
                lengths.insert(handle, u128::from(info.length));
            }
        }
    }
    Ok(lengths)
}

fn validate_attachments(
    reader: &PileSnapshot,
    overlay: Option<&OverlayReader>,
    plan: AttachmentPlan,
) -> CatalogValidation {
    let AttachmentPlan {
        texts,
        raws,
        media_type_names,
        source_chunks,
        source_snapshots,
    } = plan;
    let mut missing = BTreeSet::new();
    for handle in texts {
        match text_attachment_present(reader, overlay, handle) {
            Ok(true) => {}
            Ok(false) => {
                missing.insert(handle.raw);
            }
            Err(reason) => return CatalogValidation::Rejected(reason),
        }
    }
    for handle in raws {
        match raw_attachment_present(reader, overlay, handle) {
            Ok(true) => {}
            Ok(false) => {
                missing.insert(handle.raw);
            }
            Err(reason) => return CatalogValidation::Rejected(reason),
        }
    }
    let source_chunk_lengths = match source_chunk_storage_lengths(reader, overlay, &source_chunks) {
        Ok(lengths) => lengths,
        Err(reason) => return CatalogValidation::Rejected(reason),
    };
    if let Err(reason) =
        validate_source_snapshots(&source_chunks, &source_snapshots, &source_chunk_lengths)
    {
        return CatalogValidation::Rejected(reason);
    }
    let source_chunk_handles: BTreeSet<_> =
        source_chunks.values().map(|(_, handle)| *handle).collect();
    for handle in source_chunk_handles {
        if !source_chunk_lengths.contains_key(&handle) {
            missing.insert(handle.raw);
        }
    }
    for handle in media_type_names {
        let name = match read_text_attachment(reader, overlay, handle) {
            Ok(Some(name)) => name,
            Ok(None) => {
                missing.insert(handle.raw);
                continue;
            }
            Err(reason) => return CatalogValidation::Rejected(reason),
        };
        let normalized = match files::normalize_media_type(&name) {
            Ok(value) => value,
            Err(error) => {
                return CatalogValidation::Rejected(format!(
                    "invalid canonical media type name {name:?}: {error}"
                ));
            }
        };
        if normalized != name {
            return CatalogValidation::Rejected(format!(
                "media type name {name:?} is not canonical; expected {normalized:?}"
            ));
        }
    }
    if !missing.is_empty() {
        return CatalogValidation::Pending { missing };
    }
    CatalogValidation::Accepted
}

fn validate_catalog_with_overlay(
    reader: &PileSnapshot,
    overlay: Option<&OverlayReader>,
    facts: &TribleSet,
) -> Result<CatalogValidation> {
    let plan = match validate_structure(facts) {
        Ok(plan) => plan,
        Err(error) => return Ok(CatalogValidation::Rejected(format!("{error:#}"))),
    };
    Ok(validate_attachments(reader, overlay, plan))
}

/// Validate one complete materialized Archive catalog.
///
/// The immutable graph is proved before attachment residency is inspected, so
/// malformed data can never be concealed behind a missing blob. A pointer
/// fact with no `resolved_to` edge is a valid unresolved external asset and is
/// therefore accepted rather than reported as pending.
pub fn validate_catalog(reader: &PileSnapshot, facts: &TribleSet) -> Result<CatalogValidation> {
    validate_catalog_with_overlay(reader, None, facts)
}

/// Validate one complete Archive catalog directly over its logical Succinct
/// cover.
///
/// Exact ontology comparison walks the cover's canonical deduplicated EAV
/// stream, so validation does not rebuild the six in-memory PATCH indexes of
/// a [`TribleSet`].
pub fn validate_succinct_catalog(
    reader: &PileSnapshot,
    facts: &UnionArchive<OrderedUniverse>,
) -> Result<CatalogValidation> {
    let plan = match validate_succinct_structure(facts) {
        Ok(plan) => plan,
        Err(error) => return Ok(CatalogValidation::Rejected(format!("{error:#}"))),
    };
    Ok(validate_attachments(reader, None, plan))
}

/// Preflight the exact staged union without writing its attachments.
///
/// Existing handles resolve through `reader`; blobs carried by `fragment`
/// resolve through its immutable in-memory overlay. The returned facts are the
/// exact candidate set that was validated.
pub fn validate_catalog_union(
    reader: &PileSnapshot,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<(TribleSet, CatalogValidation)> {
    let mut union = current.clone();
    union += fragment.facts().clone();
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .snapshot()
        .expect("MemoryBlobStore reader creation is infallible");
    let validation = validate_catalog_with_overlay(reader, Some(&overlay), &union)?;
    Ok((union, validation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hifitime::Epoch;
    use std::fs::File;
    use triblespace::core::blob::encodings::succinctarchive::SuccinctArchive;
    use triblespace::core::repo::pile::Pile;
    use triblespace::prelude::inlineencodings::Handle;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).expect("test ids are non-nil")
    }

    fn instant(seconds: f64) -> Inline<NsTAIInterval> {
        let epoch = Epoch::from_unix_seconds(seconds);
        (epoch, epoch).try_to_inline().expect("valid interval")
    }

    fn text(value: &str) -> Fragment {
        text_fact(
            schema::content_fact::modality::TEXT,
            schema::content_fact::direction::IN,
            value,
        )
        .unwrap()
    }

    fn one_part(value: &str) -> Fragment {
        content_part(0, text(value), None).unwrap()
    }

    fn projection(parts: Fragment) -> Fragment {
        source_projection(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            "session:test",
            br#"{"type":"test"}"#.as_slice(),
            block([], None, parts).unwrap(),
        )
        .unwrap()
    }

    fn empty_reader() -> (tempfile::TempDir, PileSnapshot) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("empty.pile");
        File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let reader = pile.snapshot().unwrap();
        pile.close().unwrap();
        (directory, reader)
    }

    fn validate_fragment(fragment: &Fragment) -> CatalogValidation {
        let (_directory, reader) = empty_reader();
        validate_catalog_union(&reader, &TribleSet::new(), fragment)
            .unwrap()
            .1
    }

    fn without_blobs(fragment: Fragment) -> Fragment {
        let (_, facts, metafacts, _) = fragment.into_parts();
        Fragment::from_parts(facts, metafacts, Default::default())
    }

    #[test]
    fn part_ordinals_preserve_order_and_repeated_equal_facts() {
        let a = text("a");
        let b = text("b");

        let mut ab = Fragment::empty();
        ab += content_part(0, a.clone(), None).unwrap();
        ab += content_part(1, b.clone(), None).unwrap();
        let ab = block([], None, ab).unwrap();

        let mut ba = Fragment::empty();
        ba += content_part(0, b, None).unwrap();
        ba += content_part(1, a.clone(), None).unwrap();
        let ba = block([], None, ba).unwrap();
        assert_ne!(ab.root(), ba.root(), "part order is semantic");

        let fact = a.root().unwrap();
        let mut repeated = Fragment::empty();
        repeated += content_part(0, a.clone(), None).unwrap();
        repeated += content_part(1, a, None).unwrap();
        let repeated = block([], None, repeated).unwrap();
        let root = repeated.root().unwrap();
        let parts: Vec<Id> = find!(
            part: Id,
            pattern!(&repeated, [{ root @ schema::block::contains: ?part }])
        )
        .collect();
        assert_eq!(parts.len(), 2, "equal payloads at two positions survive");
        for part in parts {
            assert!(exists!(pattern!(&repeated, [{
                part @ schema::content_part::fact: &fact
            }])));
        }
    }

    #[test]
    fn raw_only_receipt_projects_to_the_canonical_bottom_block() {
        let receipt = projection(Fragment::empty());
        let receipt_id = receipt.root().unwrap();
        let block = find!(
            (block: Id),
            pattern!(&receipt, [{
                receipt_id @ schema::source_projection::projects_to: ?block
            }])
        )
        .next()
        .map(|(block,)| block)
        .unwrap();
        assert!(!exists!(pattern!(&receipt, [{
            block @ schema::block::contains: _?part
        }])));

        let (_directory, reader) = empty_reader();
        let (_, validation) = validate_catalog_union(&reader, &TribleSet::new(), &receipt).unwrap();
        assert_eq!(validation, CatalogValidation::Accepted);
    }

    #[test]
    fn archive_vocabulary_is_queryable_collection_data() {
        let mut vocabulary = vocabulary_fragment();
        let text = schema::content_fact::modality::TEXT;
        let alias = vocabulary.put::<UTF8String, _>("written text".to_owned());
        vocabulary += entity! { ExclusiveId::force_ref(&text) @
            metadata::name: alias,
        };
        let names: BTreeSet<_> = find!(
            value: TextHandle,
            pattern!(&vocabulary, [{
                text @ metadata::tag: &metadata::KIND_TAG,
                metadata::name: ?value,
            }])
        )
        .collect();
        let mut blobs = vocabulary.blobs().clone();
        let reader = blobs.snapshot().unwrap();
        let values: BTreeSet<String> = names
            .into_iter()
            .map(|name| {
                let value: anybytes::View<str> = reader.get(name).unwrap();
                value.to_string()
            })
            .collect();
        assert_eq!(
            values,
            BTreeSet::from(["text".to_owned(), "written text".to_owned()])
        );

        let (_directory, reader) = empty_reader();
        let (_, validation) =
            validate_catalog_union(&reader, &TribleSet::new(), &vocabulary).unwrap();
        assert_eq!(validation, CatalogValidation::Accepted);
    }

    #[test]
    fn source_snapshot_is_exact_path_independent_and_empty_safe() {
        let make = |path: Option<&str>| {
            source_snapshot(
                schema::source_projection::SOURCE_CLAUDE_CODE,
                "snapshot/v1/session:test",
                3,
                source_chunk(0, Bytes::from_source(b"abc".to_vec())).unwrap(),
                path.map(str::to_owned),
            )
            .unwrap()
        };
        let first = make(Some("/old/export.jsonl"));
        let moved = make(Some("/new/export.jsonl"));
        assert_eq!(first.root(), moved.root());
        assert_ne!(first.facts(), moved.facts());
        assert_eq!(validate_fragment(&first), CatalogValidation::Accepted);

        let empty = source_snapshot(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            "snapshot/v1/empty",
            0,
            Fragment::empty(),
            None,
        )
        .unwrap();
        assert_eq!(validate_fragment(&empty), CatalogValidation::Accepted);
        assert!(!exists!(pattern!(&empty, [{
            _?chunk @ schema::source_chunk::bytes: _?raw
        }])));
    }

    #[test]
    fn source_snapshot_geometry_uses_store_lengths_without_reading_payloads() {
        let wrong_total = source_snapshot(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            "snapshot/v1/wrong-total",
            2,
            source_chunk(0, Bytes::from_source(vec![1u8])).unwrap(),
            None,
        )
        .unwrap();
        let validation = validate_fragment(&wrong_total);
        match validation {
            CatalogValidation::Rejected(reason) => assert!(
                reason.contains("stores 1 bytes, expected 2"),
                "unexpected rejection: {reason}"
            ),
            other => panic!("expected length rejection, got {other:?}"),
        }

        let mut short_nonfinal = Fragment::empty();
        short_nonfinal += source_chunk(0, Bytes::from_source(vec![1u8])).unwrap();
        short_nonfinal += source_chunk(
            schema::source_chunk::CANONICAL_BYTES as u128,
            Bytes::from_source(vec![2u8]),
        )
        .unwrap();
        let short_nonfinal = source_snapshot(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            "snapshot/v1/short-nonfinal",
            schema::source_chunk::CANONICAL_BYTES as u128 + 1,
            short_nonfinal,
            None,
        )
        .unwrap();
        let validation = validate_fragment(&short_nonfinal);
        match validation {
            CatalogValidation::Rejected(reason) => assert!(
                reason.contains("stores 1 bytes, expected 8388608"),
                "unexpected rejection: {reason}"
            ),
            other => panic!("expected nonfinal length rejection, got {other:?}"),
        }
    }

    #[test]
    fn source_snapshot_rejects_gaps_duplicates_and_orphan_chunks_before_residency() {
        let canonical = schema::source_chunk::CANONICAL_BYTES as u128;
        for (label, second_offset, expected) in [
            ("gap", canonical + 1, "starts at 8388609, expected 8388608"),
            ("duplicate", 0, "starts at 0, expected 8388608"),
        ] {
            let mut chunks = Fragment::empty();
            chunks += source_chunk(0, Bytes::from_source(vec![1u8])).unwrap();
            chunks += source_chunk(second_offset, Bytes::from_source(vec![2u8])).unwrap();
            let snapshot = source_snapshot(
                schema::source_projection::SOURCE_CLAUDE_CODE,
                format!("snapshot/v1/{label}"),
                canonical + 1,
                chunks,
                None,
            )
            .unwrap();
            let snapshot = without_blobs(snapshot);
            assert!(matches!(
                validate_fragment(&snapshot),
                CatalogValidation::Rejected(reason) if reason.contains(expected)
            ));
        }

        let orphan = source_chunk(0, Bytes::from_source(vec![1u8])).unwrap();
        assert!(matches!(
            validate_fragment(&orphan),
            CatalogValidation::Rejected(reason) if reason.contains("orphan source chunk")
        ));
    }

    #[test]
    fn source_snapshot_with_absent_bytes_is_pending_not_rejected() {
        let snapshot = source_snapshot(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            "snapshot/v1/missing",
            1,
            source_chunk(0, Bytes::from_source(vec![7u8])).unwrap(),
            None,
        )
        .unwrap();
        let raw = find!(
            handle: RawHandle,
            pattern!(&snapshot, [{ _?chunk @ schema::source_chunk::bytes: ?handle }])
        )
        .next()
        .unwrap();
        let snapshot = without_blobs(snapshot);
        assert!(matches!(
            validate_fragment(&snapshot),
            CatalogValidation::Pending { missing } if missing.contains(&raw.raw)
        ));
    }

    #[test]
    fn timestamp_is_a_repeatable_annotation_not_intrinsic_state() {
        let without = block([], None, one_part("same")).unwrap();
        let with_42 = block([], Some(instant(42.0)), one_part("same")).unwrap();
        let with_43 = block([], Some(instant(43.0)), one_part("same")).unwrap();
        assert_eq!(without.root(), with_42.root());
        assert_eq!(without.root(), with_43.root());
        let root = without.root().unwrap();
        assert!(!exists!(pattern!(&without, [{
            root @ schema::block::timestamp: _?timestamp
        }])));

        let mut observed_twice = with_42;
        observed_twice += with_43;
        let projected = source_projection(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            "timestamp-observations",
            b"{}".as_slice(),
            observed_twice,
        )
        .unwrap();
        validate_catalog_structure(&projected.into_facts()).unwrap();
    }

    #[test]
    fn source_projection_is_idempotent_but_preserves_occurrences() {
        let make = |locator: &str| {
            source_projection(
                schema::source_projection::SOURCE_CLAUDE_CODE,
                locator,
                br#"{\"type\":\"user\"}"#.as_slice(),
                block([], None, one_part("hello")).unwrap(),
            )
            .unwrap()
        };
        let first = make("session:7");
        let replay = make("session:7");
        let other_locator = make("session:8");
        let other_raw = source_projection(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            "session:7",
            b"different raw record".as_slice(),
            block([], None, one_part("hello")).unwrap(),
        )
        .unwrap();
        assert_eq!(first, replay);
        assert_ne!(first.root(), other_locator.root());
        assert_ne!(first.root(), other_raw.root());

        let projected = |projection: &Fragment| {
            let root = projection.root().unwrap();
            find!(
                block: Id,
                pattern!(projection, [{
                    root @ schema::source_projection::projects_to: ?block
                }])
            )
            .next()
            .unwrap()
        };
        assert_eq!(projected(&first), projected(&other_locator));
        assert_eq!(projected(&first), projected(&other_raw));
    }

    #[test]
    fn occurrence_annotations_do_not_change_projection_identity() {
        let projection = source_projection(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            "session:7",
            b"raw".as_slice(),
            block([], None, one_part("hello")).unwrap(),
        )
        .unwrap();
        let root = projection.root().unwrap();
        let annotated = annotate_source_projection(
            projection,
            ProjectionAnnotations {
                semantic_predecessor_support: vec![id(8)],
                source_timestamp: Some(instant(42.0)),
                author: Some(id(9)),
                experiencer: Some(id(10)),
                raw_author: Some("human".into()),
                raw_role: Some("user".into()),
                raw_model: Some("model-v1".into()),
                source_path: Some("/moved/export.jsonl".into()),
            },
        )
        .unwrap();
        assert_eq!(annotated.root(), Some(root));
        assert!(exists!(pattern!(&annotated, [{
            root @ schema::source_projection::author: &id(9),
            schema::source_projection::experiencer: &id(10),
        }])));
        assert!(exists!(pattern!(&annotated, [{
            root @ files_schema::file::source_path: _?path
        }])));
    }

    #[test]
    fn semantic_predecessor_support_must_project_to_a_direct_predecessor() {
        let parent = block([], None, one_part("parent")).unwrap();
        let parent_id = parent.root().unwrap();
        let unrelated = block([], None, one_part("unrelated")).unwrap();
        let child = block([parent_id], None, one_part("child")).unwrap();

        let parent_receipt = source_projection(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            "session:parent",
            b"parent".as_slice(),
            parent,
        )
        .unwrap();
        let unrelated_receipt = source_projection(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            "session:unrelated",
            b"unrelated".as_slice(),
            unrelated,
        )
        .unwrap();
        let unrelated_receipt_id = unrelated_receipt.root().unwrap();
        let child_receipt = source_projection(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            "session:child",
            b"child".as_slice(),
            child,
        )
        .and_then(|projection| {
            annotate_source_projection(
                projection,
                ProjectionAnnotations {
                    semantic_predecessor_support: vec![unrelated_receipt_id],
                    ..ProjectionAnnotations::default()
                },
            )
        })
        .unwrap();

        let mut fragment = parent_receipt;
        fragment += unrelated_receipt;
        fragment += child_receipt;
        let (_directory, reader) = empty_reader();
        let (_, validation) =
            validate_catalog_union(&reader, &TribleSet::new(), &fragment).unwrap();
        assert!(matches!(
            validation,
            CatalogValidation::Rejected(reason) if reason.contains("for unrelated block")
        ));
    }

    #[test]
    fn binary_facts_share_files_media_type_entities() {
        let fact = blob_fact(
            schema::content_fact::modality::IMAGE,
            schema::content_fact::direction::IN,
            b"png".as_slice(),
            "IMAGE/PNG; charset=binary",
        )
        .unwrap();
        let root = fact.root().unwrap();
        let media_types: Vec<Id> = find!(
            media_type: Id,
            pattern!(&fact, [{ root @ schema::content_fact::media_type: ?media_type }])
        )
        .collect();
        assert_eq!(media_types.len(), 1);
        assert!(exists!(pattern!(&fact, [{
            media_types[0] @ metadata::tag: &files_schema::KIND_MEDIA_TYPE
        }])));
    }

    #[test]
    fn only_the_canonical_bottom_block_may_be_content_free() {
        let bottom = block([], None, Fragment::empty()).unwrap();
        let predecessor = block([], None, one_part("predecessor")).unwrap();
        let predecessor_id = predecessor.root().unwrap();

        assert!(block([predecessor_id], None, Fragment::empty()).is_err());
        assert!(block([], Some(instant(42.0)), Fragment::empty()).is_err());

        let invalid_core = entity! { _ @
            schema::block::previous: &predecessor_id,
        };
        let invalid = attach_kind(invalid_core, schema::block::KIND, "block").unwrap();
        let invalid_id = invalid.root().unwrap();
        let receipt = source_projection(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            "invalid:content-free-child",
            b"{}".as_slice(),
            invalid,
        )
        .unwrap();
        let mut catalog = bottom;
        catalog += predecessor;
        catalog += receipt;
        let (_directory, reader) = empty_reader();
        let (_, validation) = validate_catalog_union(&reader, &TribleSet::new(), &catalog).unwrap();
        assert!(matches!(
            validation,
            CatalogValidation::Rejected(reason)
                if reason.contains("is not the predecessor-free, timeless canonical bottom")
        ));
        assert!(exists!(pattern!(&catalog, [{
            invalid_id @ schema::block::previous: &predecessor_id
        }])));
    }

    #[test]
    fn kind_markers_do_not_participate_in_intrinsic_ids() {
        let fact = text("identity");
        let fact_id = fact.root().unwrap();
        let payload = find!(
            payload: Inline<Handle<UTF8String>>,
            pattern!(&fact, [{
                fact_id @ schema::content_fact::payload: ?payload
            }])
        )
        .next()
        .unwrap();
        let core = entity! { _ @
            schema::content_fact::modality: &schema::content_fact::modality::TEXT,
            schema::content_fact::direction: &schema::content_fact::direction::IN,
            schema::content_fact::payload: payload,
        };
        assert_eq!(core.root(), Some(fact_id));
        assert!(exists!(pattern!(&fact, [{
            fact_id @ metadata::tag: &schema::content_fact::KIND
        }])));
    }

    #[test]
    fn semantic_response_edges_participate_in_part_identity() {
        let target = content_part(0, text("call"), None).unwrap().root().unwrap();
        let unrelated = content_part(1, text("result"), None).unwrap();
        let related = content_part(1, text("result"), Some(target)).unwrap();
        assert_ne!(unrelated.root(), related.root());
    }

    #[test]
    fn resolving_pointer_bytes_keeps_the_intrinsic_root() {
        let fact = asset_pointer_fact(
            schema::content_fact::modality::IMAGE,
            schema::content_fact::direction::IN,
            id(11),
            "asset-42",
            Some("image/png"),
            Some(3),
        )
        .unwrap();
        let root = fact.root().unwrap();
        let resolved = resolve_pointer_fact(fact, b"png".as_slice()).unwrap();
        assert_eq!(resolved.root(), Some(root));
        let handles: Vec<Inline<Handle<RawBytes>>> = find!(
            handle: Inline<Handle<RawBytes>>,
            pattern!(&resolved, [{ root @ schema::content_fact::resolved_to: ?handle }])
        )
        .collect();
        assert_eq!(handles.len(), 1);
    }

    #[test]
    fn a_part_selects_the_unique_pointer_resolution_in_its_identity() {
        let make = |bytes: &'static [u8]| {
            asset_pointer_fact(
                schema::content_fact::modality::FILE,
                schema::content_fact::direction::IN,
                id(11),
                "sandbox:/same",
                Some("application/octet-stream"),
                Some(bytes.len() as u128),
            )
            .and_then(|fact| resolve_pointer_fact(fact, bytes))
            .unwrap()
        };
        let first = make(b"first");
        let replay = make(b"first");
        let second = make(b"other");
        assert_eq!(first, replay);
        assert_eq!(first.root(), second.root());

        let first = content_part(0, first, None).unwrap();
        let replay = content_part(0, replay, None).unwrap();
        let second = content_part(0, second, None).unwrap();
        assert_eq!(first, replay);
        assert_ne!(first.root(), second.root());

        for part in [first, second] {
            let root = part.root().unwrap();
            let resolutions: Vec<Inline<Handle<RawBytes>>> = find!(
                resolution: Inline<Handle<RawBytes>>,
                pattern!(&part, [{
                    root @ schema::content_part::resolution: ?resolution
                }])
            )
            .collect();
            assert_eq!(resolutions.len(), 1);
        }
    }

    #[test]
    fn staged_complete_projection_is_accepted_without_writing() {
        let (_directory, reader) = empty_reader();
        let fragment = projection(one_part("hello from the staged overlay"));
        let (union, validation) =
            validate_catalog_union(&reader, &TribleSet::new(), &fragment).unwrap();
        assert_eq!(union, fragment.facts().clone());
        assert_eq!(validation, CatalogValidation::Accepted);
    }

    #[test]
    fn complete_graph_without_attachments_is_pending() {
        let (_directory, reader) = empty_reader();
        let fragment = projection(one_part("hello without resident bytes"));
        validate_catalog_structure(fragment.facts()).unwrap();
        let validation = validate_catalog(&reader, fragment.facts()).unwrap();
        let CatalogValidation::Pending { missing } = validation else {
            panic!("complete graph with absent blobs should be pending");
        };
        assert_eq!(missing.len(), 3, "payload, locator, and raw source record");
    }

    #[test]
    fn succinct_cover_validates_the_same_exact_logical_catalog() {
        let (_directory, reader) = empty_reader();
        let fragment = projection(one_part("hello from a succinct cover"));
        let segment = SuccinctArchive::<OrderedUniverse>::from(fragment.facts());
        let cover = UnionArchive::new(vec![segment.clone(), segment]);

        let validation = validate_succinct_catalog(&reader, &cover).unwrap();
        let CatalogValidation::Pending { missing } = validation else {
            panic!("complete succinct graph with absent blobs should be pending");
        };
        assert_eq!(missing.len(), 3, "payload, locator, and raw source record");
    }

    #[test]
    fn structural_rejection_dominates_missing_attachments() {
        let (_directory, reader) = empty_reader();
        let malformed = projection(content_part(1, text("ordinal gap"), None).unwrap());
        let validation = validate_catalog(&reader, malformed.facts()).unwrap();
        assert!(matches!(
            validation,
            CatalogValidation::Rejected(reason) if reason.contains("non-contiguous part ordinals")
        ));
    }

    #[test]
    fn unresolved_and_ambiguously_resolved_pointers_are_valid() {
        let (_directory, reader) = empty_reader();
        let unresolved = asset_pointer_fact(
            schema::content_fact::modality::IMAGE,
            schema::content_fact::direction::IN,
            id(11),
            "vendor:asset-42",
            Some("image/png"),
            Some(3),
        )
        .unwrap();
        let unresolved = projection(content_part(0, unresolved, None).unwrap());
        let (_, validation) =
            validate_catalog_union(&reader, &TribleSet::new(), &unresolved).unwrap();
        assert_eq!(validation, CatalogValidation::Accepted);

        let resolved = asset_pointer_fact(
            schema::content_fact::modality::IMAGE,
            schema::content_fact::direction::IN,
            id(11),
            "vendor:asset-42",
            None,
            None,
        )
        .and_then(|fact| resolve_pointer_fact(fact, b"first".as_slice()))
        .and_then(|fact| resolve_pointer_fact(fact, b"second".as_slice()))
        .unwrap();
        let resolved = projection(content_part(0, resolved, None).unwrap());
        let (_, validation) =
            validate_catalog_union(&reader, &TribleSet::new(), &resolved).unwrap();
        assert_eq!(validation, CatalogValidation::Accepted);
    }

    #[test]
    fn exact_coverage_rejects_orphan_content() {
        let (_directory, reader) = empty_reader();
        let mut fragment = projection(one_part("reachable"));
        fragment += text("orphan");
        let (_, validation) =
            validate_catalog_union(&reader, &TribleSet::new(), &fragment).unwrap();
        assert!(matches!(
            validation,
            CatalogValidation::Rejected(reason) if reason.contains("orphan content fact")
        ));
    }

    #[test]
    fn source_paths_are_additive_occurrence_annotations() {
        let (_directory, reader) = empty_reader();
        let projection = projection(one_part("moved export"));
        let root = projection.root().unwrap();
        let projection = annotate_source_projection(
            projection,
            ProjectionAnnotations {
                source_path: Some("/first/export.jsonl".into()),
                ..ProjectionAnnotations::default()
            },
        )
        .and_then(|projection| {
            annotate_source_projection(
                projection,
                ProjectionAnnotations {
                    source_path: Some("/second/export.jsonl".into()),
                    ..ProjectionAnnotations::default()
                },
            )
        })
        .unwrap();
        assert_eq!(projection.root(), Some(root));
        let (_, validation) =
            validate_catalog_union(&reader, &TribleSet::new(), &projection).unwrap();
        assert_eq!(validation, CatalogValidation::Accepted);
    }

    #[test]
    fn closed_modality_vocabulary_is_enforced_before_residency() {
        let (_directory, reader) = empty_reader();
        let unknown = text_fact(id(12), schema::content_fact::direction::IN, "unknown").unwrap();
        let fragment = projection(content_part(0, unknown, None).unwrap());
        let validation = validate_catalog(&reader, fragment.facts()).unwrap();
        assert!(matches!(
            validation,
            CatalogValidation::Rejected(reason) if reason.contains("unknown modality")
        ));
    }
}
