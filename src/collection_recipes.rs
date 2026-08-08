//! Faculties-owned collection recipe descriptors and concrete validators.
//!
//! TribleSpace core resolves authenticated collection algebra without knowing
//! any blob format. This module is the deliberately small representation seam:
//! an in-process catalog of free validators, plus validation exhaust which can
//! be shared by immutable pile snapshots. There is no persisted plugin or
//! omnibus recipe trait here.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};

use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::succinctarchive::{
    SuccinctArchiveBlob, SuccinctArchiveRawBuildError,
};
use triblespace::core::blob::{Blob, BlobEncoding, IntoBlob, TryFromBlob};
use triblespace::core::collection::simplearchive_union::{
    validate_commit, validate_merge, TRIBLE_SET_UNION_RECIPE_V1,
};
use triblespace::core::collection::{
    CollectionClaimValidation, CollectionCommit, CollectionData, CollectionDefinition,
    CollectionDerive, CollectionMerge, CollectionValidationRequest,
};
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::InlineEncoding;
use triblespace::core::metadata::MetaDescribe;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStoreGet, BlobStoreMeta};
use triblespace_search::portable_bm25::{PortableBM25Blob, PortableBM25Index};
use triblespace_search::tokens::WordHash;

use crate::archive_bm25::{self, DeriveValidation, ARCHIVE_BLOCK_TEXT_BM25_RECIPE_V1};
use crate::schemas::blockdag;

pub(crate) type ValidationVerdict = CollectionClaimValidation<String>;

/// A concrete collection representation paired with its abstract merge law.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct CollectionKind {
    pub(crate) representation: Id,
    pub(crate) recipe: Id,
}

impl CollectionKind {
    pub(crate) fn of(definition: &CollectionDefinition) -> Self {
        Self {
            representation: definition.representation(),
            recipe: definition.recipe(),
        }
    }

    pub(crate) fn definition(self, scope: Id) -> CollectionDefinition {
        CollectionDefinition::new(scope, self.representation, self.recipe)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootPolicy {
    Committed,
    DerivedOnly,
}

/// Changes whenever the deterministic meaning of one validator changes.
///
/// A textual epoch is intentional: it is process-local cache identity, not a
/// wire-format identifier or a claim about content identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ValidatorEpoch(pub(crate) &'static str);

type CommitValidator =
    fn(&PileReader, &CollectionDefinition, &CollectionCommit) -> Result<ValidationVerdict>;
type MergeValidator =
    fn(&PileReader, &CollectionDefinition, &CollectionMerge) -> Result<ValidationVerdict>;
type DeriveValidator = fn(
    &PileReader,
    &CollectionDefinition,
    &CollectionDefinition,
    &CollectionDerive,
) -> Result<ValidationVerdict>;

#[derive(Clone, Copy)]
pub(crate) struct KindDescriptor {
    pub(crate) kind: CollectionKind,
    pub(crate) epoch: ValidatorEpoch,
    pub(crate) roots: RootPolicy,
    pub(crate) validate_commit: Option<CommitValidator>,
    pub(crate) validate_merge: MergeValidator,
}

#[derive(Clone, Copy)]
pub(crate) struct DeriveDescriptor {
    pub(crate) source: CollectionKind,
    pub(crate) target: CollectionKind,
    pub(crate) epoch: ValidatorEpoch,
    pub(crate) validate: DeriveValidator,
}

/// A small, closed catalog of validators compiled into Faculties.
///
/// The descriptor shape is intentionally data-like, but this is not a dynamic
/// registry and is never serialized into the pile. Recipe records remain the
/// ordinary collection definitions and equations understood by core.
#[derive(Clone)]
pub(crate) struct RecipeCatalog {
    kinds: BTreeMap<CollectionKind, KindDescriptor>,
    derives: BTreeMap<(CollectionKind, CollectionKind), DeriveDescriptor>,
}

impl RecipeCatalog {
    pub(crate) fn faculties() -> Self {
        Self::new(
            [
                simplearchive_descriptor(),
                succinctarchive_descriptor(),
                archive_bm25_descriptor(),
            ],
            [
                simplearchive_to_succinct_descriptor(),
                simplearchive_to_archive_bm25_descriptor(),
            ],
        )
        .expect("the built-in collection recipe catalog has unique keys")
    }

    pub(crate) fn new(
        kinds: impl IntoIterator<Item = KindDescriptor>,
        derives: impl IntoIterator<Item = DeriveDescriptor>,
    ) -> Result<Self> {
        let mut kind_map = BTreeMap::new();
        for descriptor in kinds {
            if kind_map.insert(descriptor.kind, descriptor).is_some() {
                return Err(anyhow!(
                    "duplicate collection-kind validator for representation {:X}, recipe {:X}",
                    descriptor.kind.representation,
                    descriptor.kind.recipe,
                ));
            }
        }

        let mut derive_map = BTreeMap::new();
        for descriptor in derives {
            if !kind_map.contains_key(&descriptor.source)
                || !kind_map.contains_key(&descriptor.target)
            {
                return Err(anyhow!(
                    "derive validator endpoints must both name registered collection kinds"
                ));
            }
            let key = (descriptor.source, descriptor.target);
            if derive_map.insert(key, descriptor).is_some() {
                return Err(anyhow!(
                    "duplicate derive validator for one exact source/target kind pair"
                ));
            }
        }
        Ok(Self {
            kinds: kind_map,
            derives: derive_map,
        })
    }

    /// Exact same-scope backward closure induced by registered derive edges.
    pub(crate) fn backward_definitions(
        &self,
        target: &CollectionDefinition,
    ) -> Result<Vec<CollectionDefinition>> {
        let target_kind = CollectionKind::of(target);
        if !self.kinds.contains_key(&target_kind) {
            return Err(anyhow!(
                "no validator for target representation {:X}, recipe {:X}",
                target_kind.representation,
                target_kind.recipe,
            ));
        }

        let scope = target.scope();
        let mut definitions = BTreeMap::from([(target.id(), target.clone())]);
        let mut pending = vec![target_kind];
        let mut seen = BTreeSet::from([target_kind]);
        while let Some(target_kind) = pending.pop() {
            for descriptor in self
                .derives
                .values()
                .filter(|descriptor| descriptor.target == target_kind)
            {
                let source = descriptor.source.definition(scope);
                definitions.entry(source.id()).or_insert(source);
                if seen.insert(descriptor.source) {
                    pending.push(descriptor.source);
                }
            }
        }

        // Diamonds are intentional: equivalent acyclic routes converge on one
        // set-valued closure. A cycle is not a route choice, however, and would
        // make the direction of definition dependency ill-founded. Kahn's
        // algorithm distinguishes the two without recursive traversal.
        let mut indegree: BTreeMap<CollectionKind, usize> =
            seen.iter().copied().map(|kind| (kind, 0)).collect();
        let mut outgoing: BTreeMap<CollectionKind, Vec<CollectionKind>> = BTreeMap::new();
        for descriptor in self.derives.values() {
            if seen.contains(&descriptor.source) && seen.contains(&descriptor.target) {
                *indegree
                    .get_mut(&descriptor.target)
                    .expect("reachable target has an indegree slot") += 1;
                outgoing
                    .entry(descriptor.source)
                    .or_default()
                    .push(descriptor.target);
            }
        }
        let mut ready: Vec<_> = indegree
            .iter()
            .filter_map(|(kind, degree)| (*degree == 0).then_some(*kind))
            .collect();
        let mut ordered = 0usize;
        while let Some(kind) = ready.pop() {
            ordered += 1;
            for target in outgoing.get(&kind).into_iter().flatten() {
                let degree = indegree
                    .get_mut(target)
                    .expect("reachable target has an indegree slot");
                *degree -= 1;
                if *degree == 0 {
                    ready.push(*target);
                }
            }
        }
        if ordered != seen.len() {
            return Err(anyhow!(
                "registered collection derive closure contains a cycle"
            ));
        }
        Ok(definitions.into_values().collect())
    }

    /// Validate only exact claims in `definition_ids`; all other pile noise is
    /// left Pending without touching any endpoint blob.
    pub(crate) fn validate_request(
        &self,
        exhaust: &CollectionValidationExhaust,
        reader: &PileReader,
        definition_ids: &BTreeSet<Id>,
        request: CollectionValidationRequest<'_>,
    ) -> Result<ValidationVerdict> {
        match request {
            CollectionValidationRequest::Commit { definition, claim } => {
                if !definition_ids.contains(&definition.id()) {
                    return Ok(ValidationVerdict::Pending);
                }
                let descriptor = self
                    .kinds
                    .get(&CollectionKind::of(definition))
                    .ok_or_else(|| anyhow!("closed definition has no kind validator"))?;
                exhaust.validate(claim.id(), descriptor.epoch, || match descriptor.roots {
                    RootPolicy::Committed => descriptor
                        .validate_commit
                        .ok_or_else(|| anyhow!("committed kind has no COMMIT validator"))?(
                        reader, definition, claim,
                    ),
                    RootPolicy::DerivedOnly => Ok(ValidationVerdict::Rejected(format!(
                        "collection {:X} is derived-only and rejects direct COMMIT roots",
                        definition.id(),
                    ))),
                })
            }
            CollectionValidationRequest::Merge { definition, claim } => {
                if !definition_ids.contains(&definition.id()) {
                    return Ok(ValidationVerdict::Pending);
                }
                let descriptor = self
                    .kinds
                    .get(&CollectionKind::of(definition))
                    .ok_or_else(|| anyhow!("closed definition has no kind validator"))?;
                exhaust.validate(claim.id(), descriptor.epoch, || {
                    (descriptor.validate_merge)(reader, definition, claim)
                })
            }
            CollectionValidationRequest::Derive {
                source_definition,
                target_definition,
                claim,
            } => {
                if !definition_ids.contains(&source_definition.id())
                    || !definition_ids.contains(&target_definition.id())
                {
                    return Ok(ValidationVerdict::Pending);
                }
                let key = (
                    CollectionKind::of(source_definition),
                    CollectionKind::of(target_definition),
                );
                let Some(descriptor) = self.derives.get(&key) else {
                    return Ok(ValidationVerdict::Pending);
                };
                // Backward closure is same-scope by construction. Reject an
                // exact record that somehow names incompatible scopes rather
                // than silently broadening the registered edge.
                if source_definition.scope() != target_definition.scope() {
                    return Ok(ValidationVerdict::Rejected(
                        "derive endpoints do not share an exact scope".to_owned(),
                    ));
                }
                exhaust.validate(claim.id(), descriptor.epoch, || {
                    (descriptor.validate)(reader, source_definition, target_definition, claim)
                })
            }
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ValidationCacheKey {
    claim: Id,
    epoch: ValidatorEpoch,
}

#[derive(Clone, Debug)]
enum CachedVerdict {
    Accepted,
    Rejected(String),
}

/// Explicitly owned process-local exhaust of durable validation work.
///
/// Clone this value into multiple [`CollectionSnapshot`](crate::collection_access::CollectionSnapshot)
/// opens to share validation evidence across immutable snapshots. Only
/// deterministic Accepted/Rejected results enter it. Pending residency and
/// operational errors are retried after the world changes.
#[derive(Clone, Debug, Default)]
pub struct CollectionValidationExhaust {
    entries: Arc<Mutex<HashMap<ValidationCacheKey, CachedVerdict>>>,
}

impl CollectionValidationExhaust {
    pub(crate) fn validate(
        &self,
        claim: Id,
        epoch: ValidatorEpoch,
        run: impl FnOnce() -> Result<ValidationVerdict>,
    ) -> Result<ValidationVerdict> {
        let key = ValidationCacheKey { claim, epoch };
        if let Some(verdict) = self
            .entries
            .lock()
            .map_err(|_| anyhow!("collection validation exhaust lock was poisoned"))?
            .get(&key)
            .cloned()
        {
            return Ok(match verdict {
                CachedVerdict::Accepted => ValidationVerdict::Accepted,
                CachedVerdict::Rejected(reason) => ValidationVerdict::Rejected(reason),
            });
        }

        let verdict = run()?;
        let durable = match &verdict {
            ValidationVerdict::Accepted => Some(CachedVerdict::Accepted),
            ValidationVerdict::Rejected(reason) => Some(CachedVerdict::Rejected(reason.clone())),
            ValidationVerdict::Pending => None,
        };
        if let Some(durable) = durable {
            self.entries
                .lock()
                .map_err(|_| anyhow!("collection validation exhaust lock was poisoned"))?
                .insert(key, durable);
        }
        Ok(verdict)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

pub(crate) fn simplearchive_kind() -> CollectionKind {
    CollectionKind {
        representation: <SimpleArchive as MetaDescribe>::id(),
        recipe: TRIBLE_SET_UNION_RECIPE_V1,
    }
}

pub(crate) fn succinctarchive_kind() -> CollectionKind {
    CollectionKind {
        representation: <SuccinctArchiveBlob as MetaDescribe>::id(),
        recipe: TRIBLE_SET_UNION_RECIPE_V1,
    }
}

pub(crate) fn archive_bm25_kind() -> CollectionKind {
    CollectionKind {
        representation: <PortableBM25Blob as MetaDescribe>::id(),
        recipe: ARCHIVE_BLOCK_TEXT_BM25_RECIPE_V1,
    }
}

/// Build the canonical raw-SuccinctArchive representation of one canonical
/// SimpleArchive union element.
///
/// This produces only the reproducible raw artifact. Rank9 attachment and
/// publication of the corresponding DERIVE equation remain separate
/// operations.
pub fn derive_succinctarchive_union_element(
    source: Blob<SimpleArchive>,
) -> std::result::Result<Blob<SuccinctArchiveBlob>, SuccinctArchiveRawBuildError> {
    SuccinctArchiveBlob::build_from_simple_archive(&source)
}

#[cfg(test)]
pub(crate) fn permissive_derive_catalog() -> RecipeCatalog {
    fn accept_derive(
        _: &PileReader,
        _: &CollectionDefinition,
        _: &CollectionDefinition,
        _: &CollectionDerive,
    ) -> Result<ValidationVerdict> {
        Ok(ValidationVerdict::Accepted)
    }

    RecipeCatalog::new(
        [simplearchive_descriptor(), succinctarchive_descriptor()],
        [DeriveDescriptor {
            source: simplearchive_kind(),
            target: succinctarchive_kind(),
            epoch: ValidatorEpoch("permissive-test-derive/validator-v1"),
            validate: accept_derive,
        }],
    )
    .unwrap()
}

fn simplearchive_descriptor() -> KindDescriptor {
    KindDescriptor {
        kind: simplearchive_kind(),
        epoch: ValidatorEpoch("simplearchive-union-v1/validator-v1"),
        roots: RootPolicy::Committed,
        validate_commit: Some(validate_simplearchive_commit),
        validate_merge: validate_simplearchive_merge,
    }
}

fn succinctarchive_descriptor() -> KindDescriptor {
    KindDescriptor {
        kind: succinctarchive_kind(),
        epoch: ValidatorEpoch("portable-succinctarchive-union-v2/validator-v1"),
        roots: RootPolicy::DerivedOnly,
        validate_commit: None,
        validate_merge: validate_succinctarchive_merge,
    }
}

fn archive_bm25_descriptor() -> KindDescriptor {
    KindDescriptor {
        kind: archive_bm25_kind(),
        epoch: ValidatorEpoch("archive-block-text-portable-bm25-v1/validator-v1"),
        roots: RootPolicy::DerivedOnly,
        validate_commit: None,
        validate_merge: validate_archive_bm25_merge,
    }
}

fn simplearchive_to_succinct_descriptor() -> DeriveDescriptor {
    DeriveDescriptor {
        source: simplearchive_kind(),
        target: succinctarchive_kind(),
        epoch: ValidatorEpoch("simplearchive-to-portable-succinctarchive-v2/validator-v1"),
        validate: validate_simplearchive_to_succinct,
    }
}

fn simplearchive_to_archive_bm25_descriptor() -> DeriveDescriptor {
    DeriveDescriptor {
        source: simplearchive_kind(),
        target: archive_bm25_kind(),
        epoch: ValidatorEpoch("simplearchive-to-archive-block-text-bm25-v1/validator-v1"),
        validate: validate_simplearchive_to_archive_bm25,
    }
}

fn load_blob<E>(reader: &PileReader, data: CollectionData) -> Result<Option<Blob<E>>>
where
    E: BlobEncoding,
    Handle<E>: InlineEncoding,
{
    let handle = Handle::<E>::from_hash(data);
    if reader.metadata(handle)?.is_none() {
        return Ok(None);
    }
    Ok(Some(reader.get(handle)?))
}

fn validate_simplearchive_commit(
    reader: &PileReader,
    definition: &CollectionDefinition,
    claim: &CollectionCommit,
) -> Result<ValidationVerdict> {
    let Some(data) = load_blob::<SimpleArchive>(reader, claim.data())? else {
        return Ok(ValidationVerdict::Pending);
    };
    Ok(match validate_commit(definition, claim, &data) {
        Ok(()) => ValidationVerdict::Accepted,
        Err(error) => ValidationVerdict::Rejected(error.to_string()),
    })
}

fn validate_simplearchive_merge(
    reader: &PileReader,
    definition: &CollectionDefinition,
    claim: &CollectionMerge,
) -> Result<ValidationVerdict> {
    let (low, high) = claim.inputs();
    let Some(low) = load_blob::<SimpleArchive>(reader, low)? else {
        return Ok(ValidationVerdict::Pending);
    };
    let Some(high) = load_blob::<SimpleArchive>(reader, high)? else {
        return Ok(ValidationVerdict::Pending);
    };
    let Some(result) = load_blob::<SimpleArchive>(reader, claim.result())? else {
        return Ok(ValidationVerdict::Pending);
    };
    Ok(
        match validate_merge(definition, claim, &low, &high, &result) {
            Ok(()) => ValidationVerdict::Accepted,
            Err(error) => ValidationVerdict::Rejected(error.to_string()),
        },
    )
}

fn validate_succinctarchive_merge(
    reader: &PileReader,
    definition: &CollectionDefinition,
    claim: &CollectionMerge,
) -> Result<ValidationVerdict> {
    if claim.collection() != definition.id() {
        return Ok(ValidationVerdict::Rejected(
            "succinct merge names a different collection".to_owned(),
        ));
    }
    let (low_data, high_data) = claim.inputs();
    let Some(low) = load_blob::<SuccinctArchiveBlob>(reader, low_data)? else {
        return Ok(ValidationVerdict::Pending);
    };
    let Some(high) = load_blob::<SuccinctArchiveBlob>(reader, high_data)? else {
        return Ok(ValidationVerdict::Pending);
    };
    let Some(result) = load_blob::<SuccinctArchiveBlob>(reader, claim.result())? else {
        return Ok(ValidationVerdict::Pending);
    };
    let expected = match SuccinctArchiveBlob::merge(&[low, high]) {
        Ok(expected) => expected,
        Err(error) => {
            return Ok(ValidationVerdict::Rejected(format!(
                "invalid canonical raw SuccinctArchive merge input: {error}"
            )))
        }
    };
    Ok(if result.bytes == expected.bytes {
        ValidationVerdict::Accepted
    } else {
        ValidationVerdict::Rejected(
            "succinct merge result is not the exact canonical input union".to_owned(),
        )
    })
}

fn validate_simplearchive_to_succinct(
    reader: &PileReader,
    source_definition: &CollectionDefinition,
    target_definition: &CollectionDefinition,
    claim: &CollectionDerive,
) -> Result<ValidationVerdict> {
    if claim.source() != source_definition.id() || claim.target() != target_definition.id() {
        return Ok(ValidationVerdict::Rejected(
            "derive record does not name its exact definitions".to_owned(),
        ));
    }
    let (input, output) = claim.mapping();
    let Some(source) = load_blob::<SimpleArchive>(reader, input)? else {
        return Ok(ValidationVerdict::Pending);
    };
    let Some(target) = load_blob::<SuccinctArchiveBlob>(reader, output)? else {
        return Ok(ValidationVerdict::Pending);
    };
    let expected = match derive_succinctarchive_union_element(source) {
        Ok(expected) => expected,
        Err(error) => {
            return Ok(ValidationVerdict::Rejected(format!(
                "invalid canonical SimpleArchive derive input: {error}"
            )))
        }
    };
    Ok(if target.bytes == expected.bytes {
        ValidationVerdict::Accepted
    } else {
        ValidationVerdict::Rejected(
            "derive output is not the exact canonical projection of its source".to_owned(),
        )
    })
}

type AttachedArchiveBM25 =
    PortableBM25Index<triblespace::core::inline::encodings::genid::GenId, WordHash>;

fn validate_archive_bm25_merge(
    reader: &PileReader,
    definition: &CollectionDefinition,
    claim: &CollectionMerge,
) -> Result<ValidationVerdict> {
    if definition.scope() != blockdag::DEFAULT_SCOPE_ID
        || CollectionKind::of(definition) != archive_bm25_kind()
    {
        return Ok(ValidationVerdict::Rejected(
            "Archive BM25 merge definition does not name the exact Archive recipe".to_owned(),
        ));
    }
    if claim.collection() != definition.id() {
        return Ok(ValidationVerdict::Rejected(
            "Archive BM25 merge names a different collection".to_owned(),
        ));
    }

    let (low_data, high_data) = claim.inputs();
    let low = load_blob::<PortableBM25Blob>(reader, low_data)?;
    let high = load_blob::<PortableBM25Blob>(reader, high_data)?;
    let result = load_blob::<PortableBM25Blob>(reader, claim.result())?;

    // Parse every resident endpoint before returning Pending for another. A
    // malformed resident proof is durable rejection, not hidden by eviction.
    let low = match low {
        Some(blob) => match AttachedArchiveBM25::try_from_blob(blob) {
            Ok(index) => Some(index),
            Err(error) => {
                return Ok(ValidationVerdict::Rejected(format!(
                    "invalid Archive BM25 merge low input: {error}"
                )))
            }
        },
        None => None,
    };
    let high = match high {
        Some(blob) => match AttachedArchiveBM25::try_from_blob(blob) {
            Ok(index) => Some(index),
            Err(error) => {
                return Ok(ValidationVerdict::Rejected(format!(
                    "invalid Archive BM25 merge high input: {error}"
                )))
            }
        },
        None => None,
    };
    let result = match result {
        Some(blob) => match AttachedArchiveBM25::try_from_blob(blob) {
            Ok(index) => Some(index),
            Err(error) => {
                return Ok(ValidationVerdict::Rejected(format!(
                    "invalid Archive BM25 merge result: {error}"
                )))
            }
        },
        None => None,
    };
    let (Some(low), Some(high), Some(result)) = (low, high, result) else {
        return Ok(ValidationVerdict::Pending);
    };

    let expected = match low.merged(&high) {
        Ok(expected) => expected,
        Err(error) => {
            return Ok(ValidationVerdict::Rejected(format!(
                "Archive BM25 exact merge failed: {error}"
            )))
        }
    };
    let expected: Blob<PortableBM25Blob> = expected.to_blob();
    let result: Blob<PortableBM25Blob> = result.to_blob();
    Ok(if result.bytes == expected.bytes {
        ValidationVerdict::Accepted
    } else {
        ValidationVerdict::Rejected(
            "Archive BM25 merge result is not the exact document-union/pointwise-max join"
                .to_owned(),
        )
    })
}

fn validate_simplearchive_to_archive_bm25(
    reader: &PileReader,
    source_definition: &CollectionDefinition,
    target_definition: &CollectionDefinition,
    claim: &CollectionDerive,
) -> Result<ValidationVerdict> {
    if source_definition.scope() != blockdag::DEFAULT_SCOPE_ID
        || target_definition.scope() != blockdag::DEFAULT_SCOPE_ID
        || CollectionKind::of(source_definition) != simplearchive_kind()
        || CollectionKind::of(target_definition) != archive_bm25_kind()
    {
        return Ok(ValidationVerdict::Rejected(
            "Archive BM25 derive endpoints do not name the exact Archive recipes".to_owned(),
        ));
    }
    if claim.source() != source_definition.id() || claim.target() != target_definition.id() {
        return Ok(ValidationVerdict::Rejected(
            "Archive BM25 derive record does not name its exact definitions".to_owned(),
        ));
    }

    let (input, output) = claim.mapping();
    let Some(source) = load_blob::<SimpleArchive>(reader, input)? else {
        return Ok(ValidationVerdict::Pending);
    };
    let expected = match archive_bm25::derive_for_validation(reader, source)? {
        DeriveValidation::Ready(expected) => expected,
        DeriveValidation::Pending => return Ok(ValidationVerdict::Pending),
        DeriveValidation::Rejected(reason) => return Ok(ValidationVerdict::Rejected(reason)),
    };

    // Source structure and all selected payloads are validated before target
    // residency is consulted, so a missing cache cannot mask malformed truth.
    let Some(target) = load_blob::<PortableBM25Blob>(reader, output)? else {
        return Ok(ValidationVerdict::Pending);
    };
    let target = match AttachedArchiveBM25::try_from_blob(target) {
        Ok(target) => target,
        Err(error) => {
            return Ok(ValidationVerdict::Rejected(format!(
                "invalid Archive BM25 derive output: {error}"
            )))
        }
    };
    let target: Blob<PortableBM25Blob> = target.to_blob();
    Ok(if target.bytes == expected.bytes {
        ValidationVerdict::Accepted
    } else {
        ValidationVerdict::Rejected(
            "Archive BM25 derive output is not the exact canonical block-text projection"
                .to_owned(),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use anybytes::Bytes;
    use tempfile::TempDir;
    use triblespace::core::blob::encodings::UnknownBlob;
    use triblespace::core::inline::encodings::genid::GenId;
    use triblespace::core::repo::{BlobStore, BlobStorePut};
    use triblespace::prelude::{entity, ExclusiveId, Fragment, Inline, IntoBlob, IntoInline};
    use triblespace_search::tokens::hash_tokens;

    use super::*;
    use crate::blockdag as archive;

    struct StoredBlobs {
        _directory: TempDir,
        reader: PileReader,
    }

    impl StoredBlobs {
        fn new(blobs: impl IntoIterator<Item = Blob<UnknownBlob>>) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("archive-bm25-test.pile");
            File::create(&path).unwrap();
            let mut pile = crate::collection_access::open_pile_strict(&path).unwrap();
            for blob in blobs {
                pile.put::<UnknownBlob, _>(blob).unwrap();
            }
            pile.flush().unwrap();
            let reader = pile.reader().unwrap();
            pile.close().unwrap();
            Self {
                _directory: directory,
                reader,
            }
        }
    }

    fn source_and_attachments(fragment: Fragment) -> (Blob<SimpleArchive>, Vec<Blob<UnknownBlob>>) {
        let (facts, mut blobs) = fragment.into_facts_and_blobs();
        let source: Blob<SimpleArchive> = facts.to_blob();
        let attachments = blobs
            .reader()
            .unwrap()
            .into_iter()
            .map(|(_, blob)| blob)
            .collect();
        (source, attachments)
    }

    fn text_block(parts: &[(Id, &str)]) -> Fragment {
        let mut occurrences = Fragment::empty();
        for (ordinal, (modality, text)) in parts.iter().enumerate() {
            let fact = archive::text_fact(
                *modality,
                blockdag::content_fact::direction::IN,
                (*text).to_owned(),
            )
            .unwrap();
            occurrences += archive::content_part(ordinal as u64, fact, None).unwrap();
        }
        archive::block(std::iter::empty::<Id>(), None, occurrences).unwrap()
    }

    fn parse_archive_bm25(blob: Blob<PortableBM25Blob>) -> AttachedArchiveBM25 {
        AttachedArchiveBM25::try_from_blob(blob).unwrap()
    }

    fn derive_archive_bm25(
        reader: &PileReader,
        source: Blob<SimpleArchive>,
    ) -> Blob<PortableBM25Blob> {
        archive_bm25::derive_archive_block_text_bm25_element(reader, source).unwrap()
    }

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn kind(byte: u8) -> CollectionKind {
        CollectionKind {
            representation: id(byte),
            recipe: id(0xEE),
        }
    }

    fn kind_descriptor(kind: CollectionKind) -> KindDescriptor {
        KindDescriptor {
            kind,
            epoch: ValidatorEpoch("closure-test-kind"),
            roots: RootPolicy::Committed,
            validate_commit: Some(validate_simplearchive_commit),
            validate_merge: validate_simplearchive_merge,
        }
    }

    fn accept_derive(
        _: &PileReader,
        _: &CollectionDefinition,
        _: &CollectionDefinition,
        _: &CollectionDerive,
    ) -> Result<ValidationVerdict> {
        Ok(ValidationVerdict::Accepted)
    }

    fn derive_descriptor(source: CollectionKind, target: CollectionKind) -> DeriveDescriptor {
        DeriveDescriptor {
            source,
            target,
            epoch: ValidatorEpoch("closure-test-derive"),
            validate: accept_derive,
        }
    }

    #[test]
    fn archive_bm25_empty_corpus_and_textless_blocks_remain_documents() {
        let (empty_source, empty_attachments) = source_and_attachments(Fragment::empty());
        let empty_store = StoredBlobs::new(empty_attachments);
        let empty = parse_archive_bm25(derive_archive_bm25(&empty_store.reader, empty_source));
        assert_eq!(empty.doc_count(), 0);
        assert_eq!(empty.term_count(), 0);

        let empty_text = text_block(&[(blockdag::content_fact::modality::TEXT, "")]);
        let empty_text_id = empty_text.root().unwrap();
        let binary_fact = archive::blob_fact(
            blockdag::content_fact::modality::IMAGE,
            blockdag::content_fact::direction::IN,
            vec![0, 1, 2, 3],
            "application/octet-stream",
        )
        .unwrap();
        let binary_part = archive::content_part(0, binary_fact, None).unwrap();
        let binary_block = archive::block(std::iter::empty::<Id>(), None, binary_part).unwrap();
        let binary_id = binary_block.root().unwrap();
        let mut corpus = empty_text;
        corpus += binary_block;
        let (source, attachments) = source_and_attachments(corpus);
        let store = StoredBlobs::new(attachments);
        let index = parse_archive_bm25(derive_archive_bm25(&store.reader, source));
        let documents: BTreeSet<_> = index.document_keys().map(|doc| doc.raw).collect();
        assert_eq!(index.doc_count(), 2);
        assert_eq!(index.term_count(), 0);
        assert_eq!(
            documents,
            BTreeSet::from([
                IntoInline::<GenId>::to_inline(&empty_text_id).raw,
                IntoInline::<GenId>::to_inline(&binary_id).raw,
            ])
        );
    }

    #[test]
    fn archive_bm25_sums_repeated_part_occurrences_across_modalities() {
        let block = text_block(&[
            (blockdag::content_fact::modality::THINKING, "echo"),
            (blockdag::content_fact::modality::TOOL_RESULT, "echo"),
        ]);
        let block_id = block.root().unwrap();
        let (source, attachments) = source_and_attachments(block);
        let store = StoredBlobs::new(attachments);
        let index = parse_archive_bm25(derive_archive_bm25(&store.reader, source));
        let document: Inline<GenId> = block_id.to_inline();
        let term = hash_tokens("echo")[0];
        assert_eq!(index.doc_count(), 1);
        assert_eq!(index.term_frequency(&document, &term), 2);

        // Repeated source leaves converge rather than summing again.
        assert_eq!(index.merged(&index).unwrap(), index);
    }

    #[test]
    fn archive_bm25_derivation_commutes_with_source_union_and_carrier_merge() {
        let left = text_block(&[(blockdag::content_fact::modality::TEXT, "alpha alpha")]);
        let right = text_block(&[(blockdag::content_fact::modality::TEXT, "beta")]);
        let left_source: Blob<SimpleArchive> = left.facts().clone().to_blob();
        let right_source: Blob<SimpleArchive> = right.facts().clone().to_blob();
        let mut union = left;
        union += right;
        let (union_source, attachments) = source_and_attachments(union);
        let store = StoredBlobs::new(attachments);

        let left = parse_archive_bm25(derive_archive_bm25(&store.reader, left_source.clone()));
        let right = parse_archive_bm25(derive_archive_bm25(&store.reader, right_source.clone()));
        let direct = derive_archive_bm25(&store.reader, union_source);
        let merged: Blob<PortableBM25Blob> = left.merged(&right).unwrap().to_blob();
        let reverse: Blob<PortableBM25Blob> = right.merged(&left).unwrap().to_blob();
        assert_eq!(merged.bytes, direct.bytes);
        assert_eq!(reverse.bytes, direct.bytes);
    }

    #[test]
    fn archive_bm25_validators_are_exact_and_use_pointwise_max() {
        let source_definition = simplearchive_kind().definition(blockdag::DEFAULT_SCOPE_ID);
        let target_definition = archive_bm25_kind().definition(blockdag::DEFAULT_SCOPE_ID);
        let block = text_block(&[(blockdag::content_fact::modality::TEXT, "alpha")]);
        let (source, attachments) = source_and_attachments(block);
        let attachment_store = StoredBlobs::new(attachments.clone());
        let target = derive_archive_bm25(&attachment_store.reader, source.clone());
        let wrong_target: Blob<PortableBM25Blob> = AttachedArchiveBM25::from_exact_counts([], [])
            .unwrap()
            .to_blob();

        let mut blobs = attachments;
        blobs.push(source.clone().transmute::<UnknownBlob>());
        blobs.push(target.clone().transmute::<UnknownBlob>());
        blobs.push(wrong_target.clone().transmute::<UnknownBlob>());
        let store = StoredBlobs::new(blobs);
        let derive = CollectionDerive::new(
            source_definition.id(),
            target_definition.id(),
            source.get_handle().into(),
            target.get_handle().into(),
        );
        assert_eq!(
            validate_simplearchive_to_archive_bm25(
                &store.reader,
                &source_definition,
                &target_definition,
                &derive,
            )
            .unwrap(),
            ValidationVerdict::Accepted
        );
        let wrong_output_derive = CollectionDerive::new(
            source_definition.id(),
            target_definition.id(),
            source.get_handle().into(),
            wrong_target.get_handle().into(),
        );
        assert!(matches!(
            validate_simplearchive_to_archive_bm25(
                &store.reader,
                &source_definition,
                &target_definition,
                &wrong_output_derive,
            )
            .unwrap(),
            ValidationVerdict::Rejected(_)
        ));

        let document: Inline<GenId> = id(0x71).to_inline();
        let term = hash_tokens("maximum")[0];
        let low = AttachedArchiveBM25::from_exact_counts([document], [(document, term, 2)])
            .unwrap()
            .to_blob();
        let high = AttachedArchiveBM25::from_exact_counts([document], [(document, term, 5)])
            .unwrap()
            .to_blob();
        let joined = parse_archive_bm25(low.clone())
            .merged(&parse_archive_bm25(high.clone()))
            .unwrap();
        assert_eq!(joined.term_frequency(&document, &term), 5);
        let joined: Blob<PortableBM25Blob> = joined.to_blob();
        let merge_store = StoredBlobs::new([
            low.clone().transmute::<UnknownBlob>(),
            high.clone().transmute::<UnknownBlob>(),
            joined.clone().transmute::<UnknownBlob>(),
        ]);
        let merge = CollectionMerge::new(
            target_definition.id(),
            low.get_handle().into(),
            high.get_handle().into(),
            joined.get_handle().into(),
        );
        assert_eq!(
            validate_archive_bm25_merge(&merge_store.reader, &target_definition, &merge).unwrap(),
            ValidationVerdict::Accepted
        );
        let wrong_merge = CollectionMerge::new(
            target_definition.id(),
            low.get_handle().into(),
            high.get_handle().into(),
            low.get_handle().into(),
        );
        assert!(matches!(
            validate_archive_bm25_merge(&merge_store.reader, &target_definition, &wrong_merge)
                .unwrap(),
            ValidationVerdict::Rejected(_)
        ));

        let alien_definition = CollectionDefinition::new(
            blockdag::DEFAULT_SCOPE_ID,
            <PortableBM25Blob as MetaDescribe>::id(),
            id(0x72),
        );
        assert!(matches!(
            validate_archive_bm25_merge(&merge_store.reader, &alien_definition, &merge).unwrap(),
            ValidationVerdict::Rejected(_)
        ));
        let wrong_derive = CollectionDerive::new(
            source_definition.id(),
            id(0x73),
            source.get_handle().into(),
            target.get_handle().into(),
        );
        assert!(matches!(
            validate_simplearchive_to_archive_bm25(
                &store.reader,
                &source_definition,
                &target_definition,
                &wrong_derive,
            )
            .unwrap(),
            ValidationVerdict::Rejected(_)
        ));

        let catalog = RecipeCatalog::faculties();
        let descriptor = catalog.kinds.get(&archive_bm25_kind()).unwrap();
        assert_eq!(descriptor.roots, RootPolicy::DerivedOnly);
        assert!(descriptor.validate_commit.is_none());
        assert!(catalog
            .derives
            .contains_key(&(simplearchive_kind(), archive_bm25_kind())));
    }

    #[test]
    fn archive_bm25_missing_payload_is_pending_but_malformed_source_rejects_first() {
        let source_definition = simplearchive_kind().definition(blockdag::DEFAULT_SCOPE_ID);
        let target_definition = archive_bm25_kind().definition(blockdag::DEFAULT_SCOPE_ID);
        let absent_target: Blob<PortableBM25Blob> = AttachedArchiveBM25::from_exact_counts([], [])
            .unwrap()
            .to_blob();

        let block = text_block(&[(blockdag::content_fact::modality::TEXT, "not resident")]);
        let (source, _attachments) = source_and_attachments(block);
        let missing_store = StoredBlobs::new([source.clone().transmute::<UnknownBlob>()]);
        let missing_claim = CollectionDerive::new(
            source_definition.id(),
            target_definition.id(),
            source.get_handle().into(),
            absent_target.get_handle().into(),
        );
        assert_eq!(
            validate_simplearchive_to_archive_bm25(
                &missing_store.reader,
                &source_definition,
                &target_definition,
                &missing_claim,
            )
            .unwrap(),
            ValidationVerdict::Pending
        );

        // A canonical SimpleArchive can still carry a malformed Archive graph.
        // Its absent text payload must not downgrade structural failure to
        // Pending merely because attachment resolution happens later.
        let mut malformed_graph =
            text_block(&[(blockdag::content_fact::modality::TEXT, "also absent")]);
        let block_id = malformed_graph.root().unwrap();
        malformed_graph += entity! { ExclusiveId::force_ref(&block_id) @
            triblespace::core::metadata::name: "unexpected block field",
        };
        let (malformed_graph, _attachments) = source_and_attachments(malformed_graph);
        let malformed_graph_store =
            StoredBlobs::new([malformed_graph.clone().transmute::<UnknownBlob>()]);
        let malformed_graph_claim = CollectionDerive::new(
            source_definition.id(),
            target_definition.id(),
            malformed_graph.get_handle().into(),
            absent_target.get_handle().into(),
        );
        let verdict = validate_simplearchive_to_archive_bm25(
            &malformed_graph_store.reader,
            &source_definition,
            &target_definition,
            &malformed_graph_claim,
        )
        .unwrap();
        assert!(
            matches!(verdict, ValidationVerdict::Rejected(reason) if reason.contains("unknown attribute"))
        );

        let malformed = Blob::<SimpleArchive>::new(Bytes::from(vec![0xFF]));
        let malformed_store = StoredBlobs::new([malformed.clone().transmute::<UnknownBlob>()]);
        let malformed_claim = CollectionDerive::new(
            source_definition.id(),
            target_definition.id(),
            malformed.get_handle().into(),
            absent_target.get_handle().into(),
        );
        let verdict = validate_simplearchive_to_archive_bm25(
            &malformed_store.reader,
            &source_definition,
            &target_definition,
            &malformed_claim,
        )
        .unwrap();
        assert!(
            matches!(verdict, ValidationVerdict::Rejected(reason) if reason.contains("canonical SimpleArchive"))
        );
    }

    #[test]
    fn validation_exhaust_caches_only_durable_verdicts_and_keys_by_epoch() {
        let exhaust = CollectionValidationExhaust::default();
        let calls = AtomicUsize::new(0);
        let claim = id(1);
        let first = ValidatorEpoch("first");
        let second = ValidatorEpoch("second");

        for _ in 0..2 {
            assert_eq!(
                exhaust
                    .validate(claim, first, || {
                        calls.fetch_add(1, Ordering::Relaxed);
                        Ok(ValidationVerdict::Pending)
                    })
                    .unwrap(),
                ValidationVerdict::Pending
            );
        }
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(exhaust.len(), 0);

        assert!(exhaust
            .validate(claim, first, || {
                calls.fetch_add(1, Ordering::Relaxed);
                Err(anyhow!("operational"))
            })
            .is_err());
        assert_eq!(exhaust.len(), 0);

        assert_eq!(
            exhaust
                .validate(claim, first, || {
                    calls.fetch_add(1, Ordering::Relaxed);
                    Ok(ValidationVerdict::Accepted)
                })
                .unwrap(),
            ValidationVerdict::Accepted
        );
        assert_eq!(
            exhaust
                .validate(claim, first, || panic!("accepted verdict must be reused"))
                .unwrap(),
            ValidationVerdict::Accepted
        );
        assert_eq!(exhaust.len(), 1);

        assert_eq!(
            exhaust
                .validate(claim, second, || {
                    calls.fetch_add(1, Ordering::Relaxed);
                    Ok(ValidationVerdict::Rejected("new epoch".to_owned()))
                })
                .unwrap(),
            ValidationVerdict::Rejected("new epoch".to_owned())
        );
        assert_eq!(
            exhaust
                .validate(claim, second, || panic!("rejection must be reused"))
                .unwrap(),
            ValidationVerdict::Rejected("new epoch".to_owned())
        );
        assert_eq!(exhaust.len(), 2);
        assert_eq!(calls.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn backward_recipe_closure_rejects_cycles() {
        let a = kind(1);
        let b = kind(2);
        let catalog = RecipeCatalog::new(
            [kind_descriptor(a), kind_descriptor(b)],
            [derive_descriptor(a, b), derive_descriptor(b, a)],
        )
        .unwrap();

        let error = catalog
            .backward_definitions(&a.definition(id(3)))
            .unwrap_err();
        assert!(format!("{error:#}").contains("cycle"));
    }

    #[test]
    fn backward_recipe_closure_converges_across_a_diamond() {
        let source = kind(1);
        let left = kind(2);
        let right = kind(3);
        let target = kind(4);
        let catalog = RecipeCatalog::new(
            [
                kind_descriptor(source),
                kind_descriptor(left),
                kind_descriptor(right),
                kind_descriptor(target),
            ],
            [
                derive_descriptor(source, left),
                derive_descriptor(source, right),
                derive_descriptor(left, target),
                derive_descriptor(right, target),
            ],
        )
        .unwrap();

        let definitions = catalog
            .backward_definitions(&target.definition(id(5)))
            .unwrap();
        let actual: BTreeSet<_> = definitions
            .iter()
            .map(|definition| CollectionKind::of(definition))
            .collect();
        assert_eq!(actual, BTreeSet::from([source, left, right, target]));
    }
}
