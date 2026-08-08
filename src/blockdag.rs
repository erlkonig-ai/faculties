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

use anyhow::{anyhow, bail, Result};
use triblespace::core::metadata;
use triblespace::prelude::blobencodings::{LongString, RawBytes};
use triblespace::prelude::inlineencodings::NsTAIInterval;
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

#[cfg(test)]
mod tests {
    use super::*;
    use hifitime::Epoch;
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
}
