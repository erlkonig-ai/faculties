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
use triblespace::core::blob::{Blob, BlobEncoding};
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
            [simplearchive_descriptor(), succinctarchive_descriptor()],
            [simplearchive_to_succinct_descriptor()],
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

fn simplearchive_to_succinct_descriptor() -> DeriveDescriptor {
    DeriveDescriptor {
        source: simplearchive_kind(),
        target: succinctarchive_kind(),
        epoch: ValidatorEpoch("simplearchive-to-portable-succinctarchive-v2/validator-v1"),
        validate: validate_simplearchive_to_succinct,
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

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
