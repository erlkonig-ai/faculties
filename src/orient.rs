//! Collection-native Orient marker algebra.
//!
//! This module deliberately contains no rendering policy and no mutable
//! checkpoint abstraction. It validates and constructs only the two monotone
//! intrinsic records stored by Orient. CLI consumers compute their current
//! observation set from validated Message, Compass, and Relations catalogs,
//! then compare it with the union returned here.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Result};
use triblespace::core::metadata;
use triblespace::macros::{entity, find, pattern};
use triblespace::prelude::*;

use crate::schemas::compass::{KIND_GOAL, KIND_NOTE, KIND_STATUS_SNAPSHOT};
use crate::schemas::message::KIND_MESSAGE_ID;
use crate::schemas::orient::{observation, KIND_BASELINE, KIND_SEEN};
use crate::schemas::relations::KIND_PERSON_ID;

/// One typed upstream observation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Observation {
    pub source_kind: Id,
    pub source_item: Id,
}

impl Observation {
    pub const fn new(source_kind: Id, source_item: Id) -> Self {
        Self {
            source_kind,
            source_item,
        }
    }
}

/// Exact validated contents of the Orient collection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Catalog {
    baselines: BTreeSet<Id>,
    seen: BTreeMap<Id, BTreeSet<Observation>>,
}

impl Catalog {
    /// Whether any settled identity-equivalent anchor has a baseline.
    pub fn has_baseline<'a>(&self, personas: impl IntoIterator<Item = &'a Id>) -> bool {
        personas
            .into_iter()
            .any(|persona| self.baselines.contains(persona))
    }

    /// Union every marker stored under settled identity-equivalent anchors.
    pub fn seen<'a>(&self, personas: impl IntoIterator<Item = &'a Id>) -> BTreeSet<Observation> {
        let mut union = BTreeSet::new();
        for persona in personas {
            if let Some(markers) = self.seen.get(persona) {
                union.extend(markers);
            }
        }
        union
    }

    pub fn baselines(&self) -> &BTreeSet<Id> {
        &self.baselines
    }

    pub fn markers(&self) -> &BTreeMap<Id, BTreeSet<Observation>> {
        &self.seen
    }
}

fn baseline_core(persona: Id) -> (Fragment, Id) {
    let fragment = entity! {
        metadata::tag: &KIND_BASELINE,
        observation::persona: persona,
    };
    let id = fragment
        .root()
        .expect("Baseline(persona) has exactly one intrinsic root");
    (fragment, id)
}

fn seen_core(persona: Id, marker: Observation) -> (Fragment, Id) {
    let fragment = entity! {
        metadata::tag: &KIND_SEEN,
        observation::persona: persona,
        observation::source_kind: marker.source_kind,
        observation::source_item: marker.source_item,
    };
    let id = fragment
        .root()
        .expect("Seen(persona, source_kind, source_item) has one intrinsic root");
    (fragment, id)
}

/// Canonical intrinsic id of `Baseline(persona)`.
pub fn baseline_id(persona: Id) -> Id {
    baseline_core(persona).1
}

/// Construct canonical `Baseline(persona)`.
pub fn baseline_fragment(persona: Id) -> (Fragment, Id) {
    baseline_core(persona)
}

/// Canonical intrinsic id of one Seen marker.
pub fn seen_id(persona: Id, marker: Observation) -> Id {
    seen_core(persona, marker).1
}

/// Construct one canonical Seen marker.
pub fn seen_fragment(persona: Id, marker: Observation) -> (Fragment, Id) {
    seen_core(persona, marker)
}

/// Construct one publication containing an optional baseline and every
/// supplied marker. Repeated inputs collapse through set-union semantics.
pub fn marker_fragment(
    persona: Id,
    include_baseline: bool,
    markers: impl IntoIterator<Item = Observation>,
) -> Fragment {
    let mut fragment = Fragment::empty();
    if include_baseline {
        fragment += baseline_core(persona).0;
    }
    let markers: BTreeSet<_> = markers.into_iter().collect();
    for marker in markers {
        fragment += seen_core(persona, marker).0;
    }
    fragment
}

fn exactly_one<T>(values: Vec<T>, entity: Id, field: &str) -> Result<T> {
    let count = values.len();
    match (values.into_iter().next(), count) {
        (Some(value), 1) => Ok(value),
        _ => bail!("Orient entity {entity:x} has {count} values for {field}; expected exactly one"),
    }
}

fn ids_of_kind(facts: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: kind }])).collect()
}

fn upstream_items(
    source_kind: Id,
    message_facts: &TribleSet,
    compass_facts: &TribleSet,
    relations_facts: &TribleSet,
) -> Option<BTreeSet<Id>> {
    let facts = if source_kind == KIND_MESSAGE_ID {
        message_facts
    } else if source_kind == KIND_GOAL
        || source_kind == KIND_STATUS_SNAPSHOT
        || source_kind == KIND_NOTE
    {
        compass_facts
    } else if source_kind == KIND_PERSON_ID {
        relations_facts
    } else {
        return None;
    };
    Some(ids_of_kind(facts, source_kind))
}

/// Validate an exact materialized Orient catalog against the three exact
/// upstream catalogs from the same immutable pile snapshot.
///
/// Every record is reconstructed byte-for-byte, every entity id must be its
/// intrinsic root, personas must be declared Relations people, and source
/// items must exist under their declared existing kind. Unknown or stray facts
/// fail the final exact-set comparison.
pub fn validate_catalog(
    facts: &TribleSet,
    message_facts: &TribleSet,
    compass_facts: &TribleSet,
    relations_facts: &TribleSet,
) -> Result<Catalog> {
    let people = ids_of_kind(relations_facts, KIND_PERSON_ID);
    let baseline_ids = ids_of_kind(facts, KIND_BASELINE);
    let seen_ids = ids_of_kind(facts, KIND_SEEN);
    let mut expected = TribleSet::new();
    let mut catalog = Catalog::default();

    for id in baseline_ids {
        let persona = exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ observation::persona: ?value }])).collect(),
            id,
            "observation::persona",
        )?;
        if !people.contains(&persona) {
            bail!("Orient baseline {id:x} names undeclared persona {persona:x}");
        }
        let (record, intrinsic) = baseline_core(persona);
        if intrinsic != id {
            bail!("Orient baseline {id:x} does not match intrinsic root {intrinsic:x}");
        }
        expected += record.into_facts();
        catalog.baselines.insert(persona);
    }

    let mut item_cache = BTreeMap::<Id, BTreeSet<Id>>::new();
    for id in seen_ids {
        let persona = exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ observation::persona: ?value }])).collect(),
            id,
            "observation::persona",
        )?;
        if !people.contains(&persona) {
            bail!("Orient Seen marker {id:x} names undeclared persona {persona:x}");
        }
        let source_kind = exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ observation::source_kind: ?value }]))
                .collect(),
            id,
            "observation::source_kind",
        )?;
        let source_item = exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ observation::source_item: ?value }]))
                .collect(),
            id,
            "observation::source_item",
        )?;
        if let std::collections::btree_map::Entry::Vacant(entry) = item_cache.entry(source_kind) {
            let items = upstream_items(source_kind, message_facts, compass_facts, relations_facts)
                .ok_or_else(|| {
                    anyhow!("Orient Seen marker {id:x} uses unknown source kind {source_kind:x}")
                })?;
            entry.insert(items);
        }
        if !item_cache[&source_kind].contains(&source_item) {
            bail!("Orient Seen marker {id:x} names missing {source_kind:x} item {source_item:x}");
        }
        let marker = Observation::new(source_kind, source_item);
        let (record, intrinsic) = seen_core(persona, marker);
        if intrinsic != id {
            bail!("Orient Seen marker {id:x} does not match intrinsic root {intrinsic:x}");
        }
        expected += record.into_facts();
        catalog.seen.entry(persona).or_default().insert(marker);
    }

    if expected != *facts {
        let missing = expected.difference(facts).len();
        let unexpected = facts.difference(&expected).len();
        bail!(
            "Orient catalog is not an exact canonical ontology ({missing} missing, {unexpected} unexpected facts)"
        );
    }
    Ok(catalog)
}

/// Preflight the exact Orient union a marker publication would produce.
pub fn validate_catalog_union(
    current: &TribleSet,
    fragment: &Fragment,
    message_facts: &TribleSet,
    compass_facts: &TribleSet,
    relations_facts: &TribleSet,
) -> Result<(TribleSet, Catalog)> {
    let mut union = current.clone();
    union += fragment.facts().clone();
    let catalog = validate_catalog(&union, message_facts, compass_facts, relations_facts)?;
    Ok((union, catalog))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(id: Id, kind: Id) -> Fragment {
        entity! { ExclusiveId::force_ref(&id) @ metadata::tag: kind }
    }

    #[test]
    fn markers_are_intrinsic_and_deduplicate() {
        let persona = ufoid().id;
        let message = ufoid().id;
        let marker = Observation::new(KIND_MESSAGE_ID, message);
        assert_eq!(baseline_id(persona), baseline_fragment(persona).1);
        assert_eq!(seen_id(persona, marker), seen_fragment(persona, marker).1);

        let once = marker_fragment(persona, true, [marker]);
        let twice = marker_fragment(persona, true, [marker, marker]);
        assert_eq!(once.facts(), twice.facts());
    }

    #[test]
    fn exact_catalog_rejects_extraneous_facts_and_wrong_intrinsic_ids() {
        let persona = ufoid().id;
        let message = ufoid().id;
        let relations = anchor(persona, KIND_PERSON_ID).into_facts();
        let messages = anchor(message, KIND_MESSAGE_ID).into_facts();
        let compass = TribleSet::new();
        let valid = marker_fragment(persona, true, [Observation::new(KIND_MESSAGE_ID, message)]);
        validate_catalog(valid.facts(), &messages, &compass, &relations).unwrap();

        let mut extra = valid.facts().clone();
        let bogus = ufoid().id;
        extra +=
            entity! { ExclusiveId::force_ref(&bogus) @ metadata::tag: &KIND_BASELINE }.into_facts();
        assert!(validate_catalog(&extra, &messages, &compass, &relations).is_err());

        let mut wrong = TribleSet::new();
        wrong += entity! { ExclusiveId::force_ref(&bogus) @
            metadata::tag: &KIND_SEEN,
            observation::persona: persona,
            observation::source_kind: &KIND_MESSAGE_ID,
            observation::source_item: message,
        }
        .into_facts();
        assert!(validate_catalog(&wrong, &messages, &compass, &relations).is_err());
    }

    #[test]
    fn source_kind_and_item_must_exist() {
        let persona = ufoid().id;
        let missing = ufoid().id;
        let relations = anchor(persona, KIND_PERSON_ID).into_facts();
        let marker = marker_fragment(persona, true, [Observation::new(KIND_NOTE, missing)]);
        assert!(validate_catalog(
            marker.facts(),
            &TribleSet::new(),
            &TribleSet::new(),
            &relations,
        )
        .is_err());
    }

    #[test]
    fn equivalent_persona_anchor_set_unions_seen_markers() {
        let first = ufoid().id;
        let second = ufoid().id;
        let message = ufoid().id;
        let goal = ufoid().id;
        let message_marker = Observation::new(KIND_MESSAGE_ID, message);
        let goal_marker = Observation::new(KIND_GOAL, goal);
        let catalog = Catalog {
            baselines: BTreeSet::from([first]),
            seen: BTreeMap::from([
                (first, BTreeSet::from([message_marker])),
                (second, BTreeSet::from([goal_marker])),
            ]),
        };

        let component = BTreeSet::from([first, second]);
        assert!(catalog.has_baseline(component.iter()));
        assert_eq!(
            catalog.seen(component.iter()),
            BTreeSet::from([message_marker, goal_marker])
        );
    }
}
