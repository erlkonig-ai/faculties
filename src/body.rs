//! Canonical Body records and strict collection read model.
//!
//! Body is an immutable log of deliberate captures and sparse VLA intents.
//! Every record is intrinsically identified by its complete semantic row.  A
//! reader therefore rejects partial records, scalar conflicts, unknown
//! vocabulary, and identities derived under an obsolete hashing epoch.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace::core::collection::lww_register::{
    LwwIndex, LwwRegisterCollection, RegisterCoordinatesMapping,
};
use triblespace::core::collection::CollectionStoreExt;
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::{BlobStoreGet, BlobStoreMeta, SnapshotSource};
use triblespace::prelude::*;

use crate::legacy_hint::open_scope;
use crate::schemas::body::{capture, intent, DEFAULT_SCOPE_ID, KIND_CAPTURE, KIND_INTENT};

pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
pub type RawHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;
pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
pub type DimensionValue = Inline<inlineencodings::U256BE>;

/// One exact deliberate capture projected from the Body collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureRow {
    pub id: Id,
    pub created_at: IntervalValue,
    pub frame: Option<RawHandle>,
    pub mime: Option<String>,
    pub width: Option<DimensionValue>,
    pub height: Option<DimensionValue>,
    pub modality: String,
    pub note: Option<TextHandle>,
    pub pose: TextHandle,
}

/// One exact sparse VLA intent projected from the Body collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntentRow {
    pub id: Id,
    pub created_at: IntervalValue,
    pub text: TextHandle,
}

/// Exact semantic projection of one Body collection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BodyCatalog {
    pub captures: BTreeMap<Id, CaptureRow>,
    pub intents: BTreeMap<Id, IntentRow>,
}

/// One coherent Body source snapshot plus its maintained intent register.
///
/// Facts, exact cover, and the attachment reader are captured by one
/// collection observation. The maintained index is then attached for exactly
/// that source cover; it is cache exhaust, never additional authority.
pub struct BodySnapshot {
    facts: TribleSet,
    store_snapshot: PileSnapshot,
    catalog: BodyCatalog,
    intents: LwwIndex,
}

impl BodySnapshot {
    /// Materialized facts admitted by this exact source cover.
    pub fn facts(&self) -> &TribleSet {
        &self.facts
    }

    /// Store snapshot captured while validating this exact source view.
    pub fn store_snapshot(&self) -> &PileSnapshot {
        &self.store_snapshot
    }

    /// Strictly validated Body ontology for this snapshot.
    pub fn catalog(&self) -> &BodyCatalog {
        &self.catalog
    }

    /// Maintained order for the Body intent register.
    pub fn intent_register(&self) -> &LwwIndex {
        &self.intents
    }

    /// Consume the coherent snapshot into facts, store snapshot, catalog, and index.
    pub fn into_parts(self) -> (TribleSet, PileSnapshot, BodyCatalog, LwwIndex) {
        (self.facts, self.store_snapshot, self.catalog, self.intents)
    }
}

/// Exact maintained tag-order projection used to select the current intent.
///
/// `metadata::tag` is the identity coordinate: every intent event states the
/// single register value [`KIND_INTENT`]. `metadata::created_at` is an
/// order-preserving point interval, and [`LwwIndex`] breaks equal-time ties by
/// intrinsic event id, matching the historical JIT reader exactly. Capture
/// rows form an independent `KIND_CAPTURE` register in the same target bytes;
/// [`latest_intent`] scopes the read with `winner(KIND_INTENT)`.
pub fn intent_register_collection<S>(
    store: &mut S,
    authority: VerifyingKey,
) -> Result<LwwRegisterCollection>
where
    S: CollectionStoreExt + SnapshotSource,
    <S as SnapshotSource>::Snapshot: BlobStoreGet,
{
    let source = crate::collection_names::open_configured(store, DEFAULT_SCOPE_ID, authority)?;
    let target = store.derive(
        source,
        RegisterCoordinatesMapping::new(metadata::tag.id(), metadata::created_at.id()),
        crate::collection_names::private_policy(authority),
    )?;
    Ok(LwwRegisterCollection::new(source, target))
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn exactly_one<T>(entity: Id, field: &str, mut values: Vec<T>) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "Body entity {} has {} values for {field}; expected exactly one",
            fmt_id(entity),
            values.len()
        );
    }
    Ok(values.pop().expect("length checked above"))
}

fn at_most_one<T>(entity: Id, field: &str, mut values: Vec<T>) -> Result<Option<T>> {
    if values.len() > 1 {
        bail!(
            "Body entity {} has {} values for {field}; expected at most one",
            fmt_id(entity),
            values.len()
        );
    }
    Ok(values.pop())
}

fn validate_point(field: &str, interval: IntervalValue) -> Result<()> {
    let (start, end): (i128, i128) = interval
        .try_from_inline()
        .map_err(|error| anyhow!("decode {field}: {error:?}"))?;
    if start != end {
        bail!("{field} must be a point interval");
    }
    Ok(())
}

fn tagged_entities(facts: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(
        entity: Id,
        pattern!(facts, [{ ?entity @ metadata::tag: kind }])
    )
    .collect()
}

pub fn entity_facts(facts: &TribleSet, entity: Id) -> TribleSet {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity)
        .copied()
        .collect()
}

/// Build the canonical intrinsic record around already-stored capture
/// payload handles.
pub fn capture_record(row: &CaptureRow) -> Fragment {
    entity! {
        metadata::tag: &KIND_CAPTURE,
        metadata::created_at: row.created_at,
        capture::frame?: row.frame.as_ref(),
        capture::mime?: row.mime.as_deref(),
        capture::width?: row.width.as_ref(),
        capture::height?: row.height.as_ref(),
        capture::modality: row.modality.as_str(),
        capture::note?: row.note.as_ref(),
        capture::pose: row.pose,
    }
}

/// Build the canonical intrinsic record around an already-stored intent text.
pub fn intent_record(row: &IntentRow) -> Fragment {
    entity! {
        metadata::tag: &KIND_INTENT,
        metadata::created_at: row.created_at,
        intent::text: row.text,
    }
}

fn validate_capture_shape(row: &CaptureRow) -> Result<()> {
    validate_point("capture creation time", row.created_at)?;
    match row.modality.as_str() {
        "vision" => {
            if row.frame.is_none()
                || row.mime.is_none()
                || row.width.is_none()
                || row.height.is_none()
            {
                bail!(
                    "vision capture {} requires frame, MIME, width, and height",
                    fmt_id(row.id)
                );
            }
        }
        "audio" => {
            if row.frame.is_none() || row.mime.is_none() {
                bail!("audio capture {} requires frame and MIME", fmt_id(row.id));
            }
            if row.width.is_some() || row.height.is_some() {
                bail!(
                    "audio capture {} cannot carry image dimensions",
                    fmt_id(row.id)
                );
            }
        }
        "touch" => {
            if row.frame.is_some()
                || row.mime.is_some()
                || row.width.is_some()
                || row.height.is_some()
            {
                bail!(
                    "touch capture {} cannot carry frame, MIME, or image dimensions",
                    fmt_id(row.id)
                );
            }
        }
        other => bail!("capture {} has unknown modality {other:?}", fmt_id(row.id)),
    }
    Ok(())
}

pub fn decode_capture(space: &TribleSet, id: Id) -> Result<CaptureRow> {
    let row = CaptureRow {
        id,
        created_at: exactly_one(
            id,
            "metadata::created_at",
            find!(
                value: IntervalValue,
                pattern!(space, [{ id @ metadata::created_at: ?value }])
            )
            .collect(),
        )?,
        frame: at_most_one(
            id,
            "capture::frame",
            find!(
                value: RawHandle,
                pattern!(space, [{ id @ capture::frame: ?value }])
            )
            .collect(),
        )?,
        mime: at_most_one(
            id,
            "capture::mime",
            find!(
                value: String,
                pattern!(space, [{ id @ capture::mime: ?value }])
            )
            .collect(),
        )?,
        width: at_most_one(
            id,
            "capture::width",
            find!(
                value: DimensionValue,
                pattern!(space, [{ id @ capture::width: ?value }])
            )
            .collect(),
        )?,
        height: at_most_one(
            id,
            "capture::height",
            find!(
                value: DimensionValue,
                pattern!(space, [{ id @ capture::height: ?value }])
            )
            .collect(),
        )?,
        modality: exactly_one(
            id,
            "capture::modality",
            find!(
                value: String,
                pattern!(space, [{ id @ capture::modality: ?value }])
            )
            .collect(),
        )?,
        note: at_most_one(
            id,
            "capture::note",
            find!(
                value: TextHandle,
                pattern!(space, [{ id @ capture::note: ?value }])
            )
            .collect(),
        )?,
        pose: exactly_one(
            id,
            "capture::pose",
            find!(
                value: TextHandle,
                pattern!(space, [{ id @ capture::pose: ?value }])
            )
            .collect(),
        )?,
    };
    validate_capture_shape(&row)?;
    Ok(row)
}

pub fn decode_intent(space: &TribleSet, id: Id) -> Result<IntentRow> {
    let row = IntentRow {
        id,
        created_at: exactly_one(
            id,
            "metadata::created_at",
            find!(
                value: IntervalValue,
                pattern!(space, [{ id @ metadata::created_at: ?value }])
            )
            .collect(),
        )?,
        text: exactly_one(
            id,
            "intent::text",
            find!(
                value: TextHandle,
                pattern!(space, [{ id @ intent::text: ?value }])
            )
            .collect(),
        )?,
    };
    validate_point("intent creation time", row.created_at)?;
    Ok(row)
}

fn load_capture(space: &TribleSet, id: Id) -> Result<CaptureRow> {
    let row = decode_capture(space, id)?;
    let expected = capture_record(&row);
    let canonical = expected
        .root()
        .expect("canonical capture record has one intrinsic root");
    if canonical != id {
        bail!(
            "Body capture {} is not intrinsic; canonical identity is {}",
            fmt_id(id),
            fmt_id(canonical)
        );
    }
    if entity_facts(space, id) != *expected.facts() {
        bail!(
            "Body capture {} has facts outside its canonical immutable record",
            fmt_id(id)
        );
    }
    Ok(row)
}

fn load_intent(space: &TribleSet, id: Id) -> Result<IntentRow> {
    let row = decode_intent(space, id)?;
    let expected = intent_record(&row);
    let canonical = expected
        .root()
        .expect("canonical intent record has one intrinsic root");
    if canonical != id {
        bail!(
            "Body intent {} is not intrinsic; canonical identity is {}",
            fmt_id(id),
            fmt_id(canonical)
        );
    }
    if entity_facts(space, id) != *expected.facts() {
        bail!(
            "Body intent {} has facts outside its canonical immutable record",
            fmt_id(id)
        );
    }
    Ok(row)
}

/// Strictly project the complete collection ontology without dereferencing
/// payloads.
pub fn load_catalog(space: &TribleSet) -> Result<BodyCatalog> {
    let capture_ids = tagged_entities(space, KIND_CAPTURE);
    let intent_ids = tagged_entities(space, KIND_INTENT);
    if let Some(id) = capture_ids.intersection(&intent_ids).next() {
        bail!(
            "Body entity {} is both a capture and an intent",
            fmt_id(*id)
        );
    }

    let mut catalog = BodyCatalog::default();
    for id in capture_ids {
        catalog.captures.insert(id, load_capture(space, id)?);
    }
    for id in intent_ids {
        catalog.intents.insert(id, load_intent(space, id)?);
    }

    let accounted: usize = catalog
        .captures
        .keys()
        .chain(catalog.intents.keys())
        .map(|id| entity_facts(space, *id).len())
        .sum();
    if accounted != space.len() {
        bail!(
            "Body collection has {} facts outside canonical capture and intent records",
            space.len().saturating_sub(accounted)
        );
    }
    Ok(catalog)
}

fn read_text_from<B: BlobStoreGet>(reader: &B, handle: TextHandle) -> Result<()> {
    let _: anybytes::View<str> = reader.get(handle).context("read Body text")?;
    Ok(())
}

fn read_raw_from<B: BlobStoreGet>(reader: &B, handle: RawHandle) -> Result<()> {
    let _: anybytes::Bytes = reader.get(handle).context("read Body frame")?;
    Ok(())
}

fn validate_catalog_payloads<B: BlobStoreGet>(reader: &B, catalog: &BodyCatalog) -> Result<()> {
    for row in catalog.captures.values() {
        if let Some(frame) = row.frame {
            read_raw_from(reader, frame)
                .with_context(|| format!("read frame of Body capture {}", fmt_id(row.id)))?;
        }
        if let Some(note) = row.note {
            read_text_from(reader, note)
                .with_context(|| format!("read note of Body capture {}", fmt_id(row.id)))?;
        }
        read_text_from(reader, row.pose)
            .with_context(|| format!("read pose of Body capture {}", fmt_id(row.id)))?;
    }
    for row in catalog.intents.values() {
        read_text_from(reader, row.text)
            .with_context(|| format!("read Body intent {}", fmt_id(row.id)))?;
    }
    Ok(())
}

/// Validate the exact Body ontology and all referenced payloads.
pub fn validate_catalog(reader: &PileSnapshot, space: &TribleSet) -> Result<BodyCatalog> {
    let catalog = load_catalog(space)?;
    validate_catalog_payloads(reader, &catalog)?;
    Ok(catalog)
}

/// Validate a prospective Body fragment against a current materialized union.
/// Staged attachments are read from the fragment first; unchanged handles may
/// already exist in the durable reader.
pub fn validate_candidate(
    reader: &PileSnapshot,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<BodyCatalog> {
    let mut union = current.clone();
    union += fragment.facts().clone();
    let catalog = load_catalog(&union)?;

    let mut local = fragment.blobs().clone();
    let local_reader = local.snapshot().context("snapshot staged Body payloads")?;
    for row in catalog.captures.values() {
        if let Some(frame) = row.frame {
            if local_reader.metadata(frame)?.is_some() {
                read_raw_from(&local_reader, frame)?;
            } else {
                read_raw_from(reader, frame)?;
            }
        }
        for text in [row.note, Some(row.pose)].into_iter().flatten() {
            if local_reader.metadata(text)?.is_some() {
                read_text_from(&local_reader, text)?;
            } else {
                read_text_from(reader, text)?;
            }
        }
    }
    for row in catalog.intents.values() {
        if local_reader.metadata(row.text)?.is_some() {
            read_text_from(&local_reader, row.text)?;
        } else {
            read_text_from(reader, row.text)?;
        }
    }
    Ok(catalog)
}

/// Select the latest validated intent through the exact maintained register.
///
/// The catalog remains the authority for record shape and payload identity;
/// the index only answers which intrinsic event wins the already-established
/// total order.
pub fn latest_intent<'a>(
    catalog: &'a BodyCatalog,
    register: &LwwIndex,
) -> Result<Option<&'a IntentRow>> {
    let Some(id) = register.winner(KIND_INTENT) else {
        if catalog.intents.is_empty() {
            return Ok(None);
        }
        bail!(
            "maintained Body intent register has no winner for {} validated intent(s)",
            catalog.intents.len()
        );
    };
    catalog.intents.get(&id).map(Some).ok_or_else(|| {
        anyhow!("maintained Body intent register selected {id:x}, which is not a validated intent")
    })
}

/// Capture Body facts and attach the maintained intent LWW index for that
/// exact source cover, constructing missing derived artifacts if necessary.
pub fn materialize_indexed_collection(
    pile: &mut Pile,
    signer: &SigningKey,
) -> Result<BodySnapshot> {
    let collection = open_scope(pile, DEFAULT_SCOPE_ID, signer)?;
    let store_snapshot = pile.snapshot().context("freeze Body store snapshot")?;
    let (facts, cover) = crate::storage::read_fact_collection(collection, &store_snapshot)
        .context("read Body collection")?;
    let catalog = validate_catalog(&store_snapshot, &facts).context("validate Body collection")?;
    let intents = intent_register_collection(pile, signer.verifying_key())?
        .ensure_exact(pile, &cover)
        .map_err(|error| anyhow!("maintain Body intent register: {error}"))?;
    Ok(BodySnapshot {
        facts,
        store_snapshot,
        catalog,
        intents,
    })
}

#[cfg(test)]
mod tests {
    use hifitime::Epoch;
    use triblespace::core::id::ExclusiveId;
    use triblespace::core::inline::TryToInline;
    use triblespace::core::metadata;
    use triblespace::macros::entity;

    use super::*;

    fn at(seconds: f64) -> IntervalValue {
        let point = Epoch::from_tai_seconds(seconds);
        (point, point).try_to_inline().unwrap()
    }

    fn vision() -> Fragment {
        let mut fragment = Fragment::empty();
        let frame = fragment.put::<blobencodings::RawBytes, _>(vec![1, 2, 3]);
        let pose = fragment.put::<blobencodings::UTF8String, _>("{}".to_owned());
        let note = fragment.put::<blobencodings::UTF8String, _>("kept".to_owned());
        fragment += capture_record(&CaptureRow {
            id: KIND_CAPTURE,
            created_at: at(1.0),
            frame: Some(frame),
            mime: Some("image/png".to_owned()),
            width: Some(640_u64.to_inline()),
            height: Some(480_u64.to_inline()),
            modality: "vision".to_owned(),
            note: Some(note),
            pose,
        });
        fragment
    }

    #[test]
    fn strict_catalog_accepts_canonical_capture_and_intent_records() {
        let mut all = vision();
        let pose = all.put::<blobencodings::UTF8String, _>("touch".to_owned());
        all += capture_record(&CaptureRow {
            id: KIND_CAPTURE,
            created_at: at(2.0),
            frame: None,
            mime: None,
            width: None,
            height: None,
            modality: "touch".to_owned(),
            note: None,
            pose,
        });
        let audio = all.put::<blobencodings::RawBytes, _>(vec![4, 5]);
        let pose = all.put::<blobencodings::UTF8String, _>("audio-pose".to_owned());
        all += capture_record(&CaptureRow {
            id: KIND_CAPTURE,
            created_at: at(3.0),
            frame: Some(audio),
            mime: Some("audio/wav".to_owned()),
            width: None,
            height: None,
            modality: "audio".to_owned(),
            note: None,
            pose,
        });
        let text = all.put::<blobencodings::UTF8String, _>("lean in".to_owned());
        all += intent_record(&IntentRow {
            id: KIND_INTENT,
            created_at: at(4.0),
            text,
        });

        let catalog = load_catalog(all.facts()).unwrap();
        assert_eq!(catalog.captures.len(), 3);
        assert_eq!(catalog.intents.len(), 1);
    }

    #[test]
    fn strict_catalog_rejects_noncanonical_identity_and_unknown_vocabulary() {
        let canonical = vision();
        let wrong = Id::new([0xA1; 16]).unwrap();
        let mut forced = TribleSet::new();
        for fact in canonical.facts() {
            let mut raw = fact.data;
            raw[..16].copy_from_slice(&wrong[..]);
            forced.insert(&Trible::force_raw(raw).unwrap());
        }
        let error = load_catalog(&forced).unwrap_err();
        assert!(error.to_string().contains("is not intrinsic"));

        let unknown = entity! {
            metadata::tag: &Id::new([0xB2; 16]).unwrap(),
        };
        let error = load_catalog(unknown.facts()).unwrap_err();
        assert!(error.to_string().contains("outside canonical"));
    }

    #[test]
    fn strict_catalog_rejects_capture_shape_conflicts() {
        let pose: TextHandle = Inline::new([0xC3; 32]);
        let malformed = entity! {
            metadata::tag: &KIND_CAPTURE,
            metadata::created_at: at(1.0),
            capture::modality: "touch",
            capture::pose: pose,
            capture::mime: "image/png",
        };
        let error = load_catalog(malformed.facts()).unwrap_err();
        assert!(error.to_string().contains("touch capture"));
    }

    #[test]
    fn strict_catalog_rejects_extra_fact_on_canonical_entity() {
        let canonical = vision();
        let id = canonical.root().unwrap();
        let mut facts = canonical.facts().clone();
        facts += entity! { ExclusiveId::force_ref(&id) @
            metadata::created_at: at(9.0),
        };
        let error = load_catalog(&facts).unwrap_err();
        assert!(error.to_string().contains("expected exactly one"));
    }
}
