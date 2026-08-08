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

use anyhow::{anyhow, bail, Result};
use triblespace::core::blob::MemoryBlobStore;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::prelude::blobencodings::{LongString, RawBytes};
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
    /// Source-level predecessor receipts, including edges that could not be
    /// truthfully resolved to canonical block predecessors.
    pub previous: Vec<Id>,
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

type TextHandle = Inline<Handle<LongString>>;
type RawHandle = Inline<Handle<RawBytes>>;
type IntervalValue = Inline<NsTAIInterval>;
type OrdinalValue = Inline<U256BE>;
type OverlayReader = <MemoryBlobStore as BlobStore>::Reader;

/// Result of validating one exact materialized Archive catalog.
///
/// `Pending` is deliberately limited to attachment residency: every asserted
/// handle already fixes the missing bytes, so those bytes may arrive without
/// changing the catalog's denotation. Missing graph entities and malformed
/// facts are [`Rejected`](Self::Rejected), because repairing them requires a
/// different set of tribles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogValidation {
    /// Structure, intrinsic identities, closure, and every resident attachment
    /// are canonical.
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

/// Construct one intrinsic textual content fact.
pub fn text_fact(modality: Id, direction: Id, text: impl Into<String>) -> Result<Fragment> {
    let mut fragment = Fragment::empty();
    let payload = fragment.put::<LongString, _>(text.into());
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
    let mut fragment = Fragment::empty();
    let pointer = fragment.put::<LongString, _>(pointer.into());
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
    rooted(&fact, "content fact")?;
    let fragment = entity! { _ @
        schema::content_part::ordinal: ordinal,
        schema::content_part::fact*: fact,
        schema::content_part::responds_to?: responds_to,
    };
    attach_kind(fragment, schema::content_part::KIND, "content part")
}

/// Construct one intrinsic block from structural predecessors, an optional
/// genuine event interval, and one or more exported content parts.
pub fn block(
    predecessors: impl IntoIterator<Item = Id>,
    timestamp: Option<Inline<NsTAIInterval>>,
    parts: Fragment,
) -> Result<Fragment> {
    if parts.exports().next().is_none() {
        bail!("block must contain at least one content part");
    }
    let predecessors: Vec<_> = predecessors.into_iter().collect();
    let fragment = entity! { _ @
        schema::block::previous*: predecessors.iter(),
        schema::block::timestamp?: timestamp,
        schema::block::contains*: parts,
    };
    attach_kind(fragment, schema::block::KIND, "block")
}

/// Construct one exact source-occurrence projection receipt.
///
/// The identity is source namespace + stable locator + exact raw record bytes
/// + projected canonical block. Replaying the same record is therefore
/// naturally idempotent, while two source occurrences of one shared block stay
/// distinguishable.
pub fn source_projection<T>(
    source_namespace: Id,
    source_locator: impl Into<String>,
    raw_record: T,
    block: Fragment,
) -> Result<Fragment>
where
    T: triblespace::core::blob::IntoBlob<RawBytes>,
{
    rooted(&block, "block")?;
    let mut fragment = Fragment::empty();
    let source_locator = fragment.put::<LongString, _>(source_locator.into());
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
        .map(|value| projection.put::<LongString, _>(value));
    let raw_role = annotations
        .raw_role
        .map(|value| projection.put::<LongString, _>(value));
    let raw_model = annotations
        .raw_model
        .map(|value| projection.put::<LongString, _>(value));
    let source_path = annotations
        .source_path
        .map(|value| projection.put::<LongString, _>(value));

    projection += entity! { ExclusiveId::force_ref(&root) @
        schema::source_projection::previous*: annotations.previous.iter(),
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

fn ids_of_kind(facts: &TribleSet, kind: Id) -> BTreeSet<Id> {
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
    [
        schema::content_fact::modality::TEXT,
        schema::content_fact::modality::AUDIO,
        schema::content_fact::modality::IMAGE,
        schema::content_fact::modality::TOOL_CALL,
        schema::content_fact::modality::TOOL_RESULT,
        schema::content_fact::modality::THINKING,
        schema::content_fact::modality::EVENT,
    ]
    .contains(&value)
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
    ]
    .contains(&value)
}

fn known_direction(value: Id) -> bool {
    [
        schema::content_fact::direction::IN,
        schema::content_fact::direction::OUT,
        schema::content_fact::direction::AMBIENT,
    ]
    .contains(&value)
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
fn validate_structure(facts: &TribleSet) -> Result<AttachmentPlan> {
    let content_facts = ids_of_kind(facts, schema::content_fact::KIND);
    let content_parts = ids_of_kind(facts, schema::content_part::KIND);
    let blocks = ids_of_kind(facts, schema::block::KIND);
    let projections = ids_of_kind(facts, schema::source_projection::KIND);
    let media_types = ids_of_kind(facts, files_schema::KIND_MEDIA_TYPE);
    require_disjoint(&[
        ("content fact", &content_facts),
        ("content part", &content_parts),
        ("block", &blocks),
        ("source projection", &projections),
        ("media type", &media_types),
    ])?;

    let media_names = values_by_entity(find!(
        (entity: Id, value: TextHandle),
        pattern!(facts, [{ ?entity @ metadata::name: ?value }])
    ));
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
    let source_previous = values_by_entity(find!(
        (entity: Id, value: Id),
        pattern!(facts, [{ ?entity @ schema::source_projection::previous: ?value }])
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
        let core = entity! { _ @
            schema::content_part::ordinal: ordinal,
            schema::content_part::fact: &fact,
            schema::content_part::responds_to?: response,
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
        let timestamp = one_optional(&block_timestamps, *id, "block timestamp")?;
        if let Some(timestamp) = timestamp {
            let _: (i128, i128) = timestamp.try_from_inline().map_err(|error| {
                anyhow!("block {id:x} has invalid timestamp interval: {error:?}")
            })?;
        }
        let parts = values_for(&block_parts, *id);
        if parts.is_empty() {
            bail!("block {id:x} contains no content parts");
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
            schema::block::timestamp?: timestamp,
            schema::block::contains*: parts.iter(),
        };
        expected += ensure_intrinsic_with_kind(*id, core, schema::block::KIND, "block")?;
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
        let previous = values_for(&source_previous, *id);
        for predecessor in &previous {
            if !projections.contains(predecessor) {
                bail!("source projection {id:x} cites missing predecessor receipt {predecessor:x}");
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
            schema::source_projection::previous*: previous.iter(),
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

    if expected != *facts {
        let missing = expected.difference(facts).len();
        let unexpected = facts.difference(&expected).len();
        bail!(
            "block-DAG catalog is not an exact canonical ontology ({missing} missing, {unexpected} unexpected facts)"
        );
    }
    Ok(attachments)
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
    reader: &PileReader,
    overlay: Option<&OverlayReader>,
    handle: TextHandle,
) -> std::result::Result<Option<String>, String> {
    if overlay.is_some_and(|overlay| {
        overlay
            .metadata(handle)
            .expect("memory metadata lookup is infallible")
            .is_some()
    }) {
        let value: anybytes::View<str> = overlay
            .expect("overlay was present")
            .get(handle)
            .map_err(|error| {
                format!(
                    "invalid staged LongString attachment {}: {error}",
                    hex::encode(handle.raw)
                )
            })?;
        return Ok(Some(value.to_string()));
    }
    if reader
        .metadata(handle)
        .expect("PileReader metadata lookup is infallible")
        .is_none()
    {
        return Ok(None);
    }
    let value: anybytes::View<str> = reader.get(handle).map_err(|error| {
        format!(
            "invalid resident LongString attachment {}: {error}",
            hex::encode(handle.raw)
        )
    })?;
    Ok(Some(value.to_string()))
}

fn read_raw_attachment(
    reader: &PileReader,
    overlay: Option<&OverlayReader>,
    handle: RawHandle,
) -> std::result::Result<bool, String> {
    if overlay.is_some_and(|overlay| {
        overlay
            .metadata(handle)
            .expect("memory metadata lookup is infallible")
            .is_some()
    }) {
        let _: anybytes::Bytes =
            overlay
                .expect("overlay was present")
                .get(handle)
                .map_err(|error| {
                    format!(
                        "invalid staged RawBytes attachment {}: {error}",
                        hex::encode(handle.raw)
                    )
                })?;
        return Ok(true);
    }
    if reader
        .metadata(handle)
        .expect("PileReader metadata lookup is infallible")
        .is_none()
    {
        return Ok(false);
    }
    let _: anybytes::Bytes = reader.get(handle).map_err(|error| {
        format!(
            "invalid resident RawBytes attachment {}: {error}",
            hex::encode(handle.raw)
        )
    })?;
    Ok(true)
}

fn validate_attachments(
    reader: &PileReader,
    overlay: Option<&OverlayReader>,
    plan: AttachmentPlan,
) -> CatalogValidation {
    let mut missing = BTreeSet::new();
    let mut text_values = BTreeMap::new();
    for handle in plan.texts {
        match read_text_attachment(reader, overlay, handle) {
            Ok(Some(value)) => {
                text_values.insert(handle, value);
            }
            Ok(None) => {
                missing.insert(handle.raw);
            }
            Err(reason) => return CatalogValidation::Rejected(reason),
        }
    }
    for handle in plan.raws {
        match read_raw_attachment(reader, overlay, handle) {
            Ok(true) => {}
            Ok(false) => {
                missing.insert(handle.raw);
            }
            Err(reason) => return CatalogValidation::Rejected(reason),
        }
    }
    for handle in plan.media_type_names {
        let Some(name) = text_values.get(&handle) else {
            continue;
        };
        let normalized = match files::normalize_media_type(name) {
            Ok(value) => value,
            Err(error) => {
                return CatalogValidation::Rejected(format!(
                    "invalid canonical media type name {name:?}: {error}"
                ))
            }
        };
        if normalized != *name {
            return CatalogValidation::Rejected(format!(
                "media type name {name:?} is not canonical; expected {normalized:?}"
            ));
        }
    }
    if missing.is_empty() {
        CatalogValidation::Accepted
    } else {
        CatalogValidation::Pending { missing }
    }
}

fn validate_catalog_with_overlay(
    reader: &PileReader,
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
pub fn validate_catalog(reader: &PileReader, facts: &TribleSet) -> Result<CatalogValidation> {
    validate_catalog_with_overlay(reader, None, facts)
}

/// Preflight the exact staged union without writing its attachments.
///
/// Existing handles resolve through `reader`; blobs carried by `fragment`
/// resolve through its immutable in-memory overlay. The returned facts are the
/// exact candidate set that was validated.
pub fn validate_catalog_union(
    reader: &PileReader,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<(TribleSet, CatalogValidation)> {
    let mut union = current.clone();
    union += fragment.facts().clone();
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .reader()
        .expect("MemoryBlobStore reader creation is infallible");
    let validation = validate_catalog_with_overlay(reader, Some(&overlay), &union)?;
    Ok((union, validation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hifitime::Epoch;
    use std::fs::File;
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

    fn empty_reader() -> (tempfile::TempDir, PileReader) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("empty.pile");
        File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let reader = pile.reader().unwrap();
        pile.close().unwrap();
        (directory, reader)
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
    fn missing_timestamp_is_absence_not_a_sentinel() {
        let without = block([], None, one_part("same")).unwrap();
        let with = block([], Some(instant(42.0)), one_part("same")).unwrap();
        assert_ne!(without.root(), with.root());
        let root = without.root().unwrap();
        assert!(!exists!(pattern!(&without, [{
            root @ schema::block::timestamp: _?timestamp
        }])));
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
                previous: vec![id(8)],
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
    fn blocks_reject_empty_part_sets() {
        assert!(block([], None, Fragment::empty()).is_err());
    }

    #[test]
    fn kind_markers_do_not_participate_in_intrinsic_ids() {
        let fact = text("identity");
        let fact_id = fact.root().unwrap();
        let payload = find!(
            payload: Inline<Handle<LongString>>,
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
