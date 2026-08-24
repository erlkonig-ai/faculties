//! Stopped-world projection of the legacy `comb-state` repository DAG.
//!
//! Legacy readers selected one random cursor entity per `(stream, persona)` by
//! comparing `created_at`.  That last-write-wins read erased repository forks.
//! This planner uses repository ancestry instead: each authored legacy cursor
//! becomes an intrinsic cursor snapshot over the predecessor antichain visible
//! at its repository parents.  Sibling advances remain visible; a later
//! authored advance after a contentless merge explicitly rejoins them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::attribute::Attribute;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::inline::{Inline, InlineEncoding};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::blobencodings::UTF8String;
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;

use crate::collection_cutover::{
    project_legacy_authored_commits, FrozenLegacyBranch, FrozenSource, LegacyCommitCoordinate,
    LegacyPinCoordinate,
};
use faculties::comb::{self, CursorDraft, CursorState, CursorTrack};
use faculties::schemas::memory::{
    self as schema,
    comb::{cursor_grain, cursor_persona, cursor_position, cursor_stream, kind_comb_cursor},
};
use faculties::storage::publish_fragments;

/// Content-addressed coordinate of one legacy repository commit.
pub type LegacyCommitId = [u8; 32];

/// Pure planner input. Ordering is deliberately non-semantic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyCombDelta {
    pub commit: LegacyCommitId,
    pub parents: BTreeSet<LegacyCommitId>,
    pub facts: TribleSet,
    pub authored: bool,
}

/// Complete canonical result and its COMMIT partition keyed by authored legacy commits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CombMigrationPlan {
    pub facts: TribleSet,
    /// Contains every authored source commit, including empty partitions.
    pub facts_by_commit: BTreeMap<LegacyCommitId, TribleSet>,
    /// Exact planner correspondence; it is deliberately not asserted in the
    /// strict Comb scope because `metadata::anchor` is not cursor state.
    pub aliases: BTreeMap<Id, Id>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LegacyCursor {
    track: CursorTrack,
    state: CursorState,
    observed_at: BTreeSet<faculties::comb::IntervalValue>,
}

#[derive(Clone, Debug, Default)]
struct PlannerState {
    snapshot: TribleSet,
    tracks: BTreeMap<CursorTrack, BTreeSet<Id>>,
    aliases: BTreeMap<Id, Id>,
}

#[derive(Default)]
struct PlannerContext {
    graph: BTreeMap<Id, BTreeSet<Id>>,
    rows: BTreeMap<Id, (CursorTrack, CursorState)>,
    raw_by_commit: BTreeMap<LegacyCommitId, TribleSet>,
}

/// Assign each canonical assertion to its least authored source coordinate.
/// Every authored source retains a slot, including authored empty commits.
fn disjoint_first_witness_partition(
    by_commit: BTreeMap<LegacyCommitId, TribleSet>,
) -> (TribleSet, BTreeMap<LegacyCommitId, TribleSet>) {
    let mut union = TribleSet::new();
    let mut partition = BTreeMap::new();
    for (commit, facts) in by_commit {
        let unique = facts.difference(&union);
        union += unique.clone();
        partition.insert(commit, unique);
    }
    (union, partition)
}

/// Plan the complete legacy Comb repository DAG using only supplied facts and
/// ancestry. `created_at` is preserved as provenance and never orders heads.
pub fn plan_legacy_comb(
    deltas: impl IntoIterator<Item = LegacyCombDelta>,
) -> Result<CombMigrationPlan> {
    let deltas: Vec<_> = deltas.into_iter().collect();
    let ordered = topological(&deltas)?;
    let mut context = PlannerContext::default();
    for delta in &deltas {
        if delta.authored {
            context.raw_by_commit.entry(delta.commit).or_default();
        } else if !delta.facts.is_empty() {
            bail!(
                "contentless Comb merge {} carries authored facts",
                commit_hex(delta.commit)
            );
        }
    }

    let by_commit: BTreeMap<_, _> = deltas.iter().map(|delta| (delta.commit, delta)).collect();
    let mut states = BTreeMap::<LegacyCommitId, PlannerState>::new();
    for commit in ordered {
        let delta = by_commit[&commit];
        let mut state = merge_parent_states(delta, &states, &context.graph)?;
        let parent_snapshot = state.snapshot.clone();
        state.snapshot += delta.facts.clone();
        validate_delta_shape(&state.snapshot, delta)?;
        if delta.authored {
            project_authored_delta(delta, &parent_snapshot, &mut state, &mut context)
                .with_context(|| format!("project legacy Comb commit {}", commit_hex(commit)))?;
        }
        states.insert(commit, state);
    }

    let (facts, facts_by_commit) = disjoint_first_witness_partition(context.raw_by_commit);
    comb::load_catalog(&facts).context("validate globally planned Comb cursor DAG")?;
    let mut aliases = BTreeMap::new();
    for state in states.values() {
        for (&legacy, &canonical) in &state.aliases {
            if let Some(previous) = aliases.insert(legacy, canonical) {
                if previous != canonical {
                    bail!(
                        "legacy Comb alias {legacy:X} resolves to both {previous:X} and {canonical:X}"
                    );
                }
            }
        }
    }
    Ok(CombMigrationPlan {
        facts,
        facts_by_commit,
        aliases,
    })
}

fn topological(deltas: &[LegacyCombDelta]) -> Result<Vec<LegacyCommitId>> {
    let mut by_commit = BTreeMap::new();
    for delta in deltas {
        if by_commit.insert(delta.commit, delta).is_some() {
            bail!(
                "legacy Comb DAG repeats commit {}",
                commit_hex(delta.commit)
            );
        }
    }
    let mut remaining = BTreeMap::new();
    let mut children: BTreeMap<LegacyCommitId, BTreeSet<LegacyCommitId>> = BTreeMap::new();
    for delta in deltas {
        for parent in &delta.parents {
            if !by_commit.contains_key(parent) {
                bail!(
                    "legacy Comb commit {} names parent {} outside the captured DAG",
                    commit_hex(delta.commit),
                    commit_hex(*parent)
                );
            }
            children.entry(*parent).or_default().insert(delta.commit);
        }
        remaining.insert(delta.commit, delta.parents.len());
    }
    let mut ready: BTreeSet<_> = remaining
        .iter()
        .filter_map(|(&commit, &count)| (count == 0).then_some(commit))
        .collect();
    let mut ordered = Vec::with_capacity(deltas.len());
    while let Some(commit) = ready.pop_first() {
        ordered.push(commit);
        for child in children.get(&commit).into_iter().flatten() {
            let count = remaining.get_mut(child).expect("known Comb child");
            *count -= 1;
            if *count == 0 {
                ready.insert(*child);
            }
        }
    }
    if ordered.len() != deltas.len() {
        bail!("legacy Comb repository ancestry contains a cycle");
    }
    Ok(ordered)
}

fn merge_parent_states(
    delta: &LegacyCombDelta,
    states: &BTreeMap<LegacyCommitId, PlannerState>,
    graph: &BTreeMap<Id, BTreeSet<Id>>,
) -> Result<PlannerState> {
    let mut merged = PlannerState::default();
    for parent in &delta.parents {
        let state = states.get(parent).ok_or_else(|| {
            anyhow!(
                "legacy Comb parent {} was not planned before child {}",
                commit_hex(*parent),
                commit_hex(delta.commit)
            )
        })?;
        merged.snapshot += state.snapshot.clone();
        for (track, heads) in &state.tracks {
            merged
                .tracks
                .entry(track.clone())
                .or_default()
                .extend(heads.iter().copied());
        }
        for (&legacy, &canonical) in &state.aliases {
            if let Some(previous) = merged.aliases.insert(legacy, canonical) {
                if previous != canonical {
                    bail!("legacy Comb alias {legacy:X} diverges across repository parents");
                }
            }
        }
    }
    for heads in merged.tracks.values_mut() {
        *heads = frontier(heads.iter().copied(), graph);
    }
    Ok(merged)
}

fn project_authored_delta(
    delta: &LegacyCombDelta,
    parent_snapshot: &TribleSet,
    state: &mut PlannerState,
    context: &mut PlannerContext,
) -> Result<()> {
    let entities: BTreeSet<Id> = delta.facts.iter().map(|fact| *fact.e()).collect();
    let base = state.clone();
    let mut new_heads: BTreeMap<CursorTrack, BTreeSet<Id>> = BTreeMap::new();
    for legacy in entities {
        let Some(row) = parse_legacy_cursor(&state.snapshot, legacy)? else {
            continue;
        };
        let new_intrinsic = delta.facts.iter().any(|fact| {
            fact.e() == &legacy
                && is_cursor_intrinsic_attribute(*fact.a())
                && !parent_snapshot.contains(fact)
        });
        let new_observations: BTreeSet<faculties::comb::IntervalValue> = delta
            .facts
            .iter()
            .filter(|fact| fact.e() == &legacy && fact.a() == &metadata::created_at.id())
            .map(|fact| *fact.v::<inlineencodings::NsTAIInterval>())
            .collect();

        if let Some(&canonical) = base.aliases.get(&legacy) {
            if new_intrinsic {
                bail!(
                    "legacy Comb cursor {legacy:X} mutates identity fields after its authored creation"
                );
            }
            if !new_observations.is_empty() {
                let mut observations = Fragment::empty();
                for observed in new_observations {
                    observations += entity! {
                        ExclusiveId::force_ref(&canonical) @ metadata::created_at: observed
                    };
                }
                *context
                    .raw_by_commit
                    .get_mut(&delta.commit)
                    .expect("authored Comb commit") += observations;
            }
            continue;
        }

        if !new_intrinsic {
            bail!(
                "legacy Comb cursor {legacy:X} first appears without identity facts in commit {}",
                commit_hex(delta.commit)
            );
        }
        if row.observed_at.is_empty() {
            bail!("legacy Comb cursor {legacy:X} has no created_at provenance");
        }
        let predecessors = base.tracks.get(&row.track).cloned().unwrap_or_default();
        let (fragment, canonical) = comb::cursor_fragment(CursorDraft {
            stream: row.track.stream.clone(),
            persona: row.track.persona.clone(),
            position: row.state.position,
            grain: row.state.grain.clone(),
            predecessors: predecessors.clone(),
            observed_at: row.observed_at,
        })?;
        if let Some(previous) = context
            .rows
            .insert(canonical, (row.track.clone(), row.state.clone()))
        {
            if previous != (row.track.clone(), row.state.clone())
                || context.graph.get(&canonical) != Some(&predecessors)
            {
                bail!("canonical Comb id {canonical:X} was rebuilt with different semantics");
            }
        }
        context.graph.insert(canonical, predecessors);
        state.aliases.insert(legacy, canonical);
        new_heads.entry(row.track).or_default().insert(canonical);
        *context
            .raw_by_commit
            .get_mut(&delta.commit)
            .expect("authored Comb commit") += fragment;
    }
    for (track, heads) in new_heads {
        state.tracks.insert(track, heads);
    }
    Ok(())
}

fn parse_legacy_cursor(space: &TribleSet, id: Id) -> Result<Option<LegacyCursor>> {
    let tags = values(space, id, &metadata::tag);
    if !tags.contains(&inlineencodings::GenId::inline_from(kind_comb_cursor)) {
        return Ok(None);
    }
    if tags.len() != 1 {
        bail!("legacy Comb cursor {id:X} has competing kind tags");
    }
    Ok(Some(LegacyCursor {
        track: CursorTrack {
            stream: one_required(values(space, id, &cursor_stream), id, "cursor_stream")?
                .try_from_inline()
                .map_err(|error| {
                    anyhow!("decode cursor_stream on legacy Comb cursor {id:X}: {error:?}")
                })?,
            persona: one_required(values(space, id, &cursor_persona), id, "cursor_persona")?
                .try_from_inline()
                .map_err(|error| {
                    anyhow!("decode cursor_persona on legacy Comb cursor {id:X}: {error:?}")
                })?,
        },
        state: CursorState {
            position: one(values(space, id, &cursor_position), id, "cursor_position")?,
            grain: one(values(space, id, &cursor_grain), id, "cursor_grain")?
                .map(|value| {
                    value.try_from_inline().map_err(|error| {
                        anyhow!("decode cursor_grain on legacy Comb cursor {id:X}: {error:?}")
                    })
                })
                .transpose()?,
        },
        observed_at: values(space, id, &metadata::created_at),
    }))
}

fn values<V: InlineEncoding>(
    facts: &TribleSet,
    entity: Id,
    attribute: &Attribute<V>,
) -> BTreeSet<Inline<V>> {
    let mut prefix = [0u8; 32];
    prefix[..16].copy_from_slice(&entity[..]);
    prefix[16..].copy_from_slice(&attribute.id()[..]);

    // EAV is already the exact entity/attribute index; descend to that
    // prefix instead of rediscovering the slice by scanning the whole union.
    let mut values = BTreeSet::new();
    facts.eav.infixes(&prefix, |value: &[u8; 32]| {
        values.insert(Inline::new(*value));
    });
    values
}

fn one<T: Ord>(mut values: BTreeSet<T>, entity: Id, field: &str) -> Result<Option<T>> {
    if values.len() > 1 {
        bail!(
            "legacy Comb cursor {entity:X} has {} values for {field}",
            values.len()
        );
    }
    Ok(values.pop_first())
}

fn one_required<T: Ord>(values: BTreeSet<T>, entity: Id, field: &str) -> Result<T> {
    one(values, entity, field)?
        .ok_or_else(|| anyhow!("legacy Comb cursor {entity:X} is missing {field}"))
}

fn validate_delta_shape(snapshot: &TribleSet, delta: &LegacyCombDelta) -> Result<()> {
    // TribleSet iteration is EAV ordered, so an entity's delta facts are
    // contiguous and share one stopped-world tag lookup.
    let mut facts = delta.facts.iter().peekable();
    while let Some(first) = facts.next() {
        let id = *first.e();
        let tags = values(snapshot, id, &metadata::tag);
        let cursor = tags.contains(&inlineencodings::GenId::inline_from(kind_comb_cursor));
        let validate_fact = |fact: &Trible| -> Result<()> {
            if !cursor || !is_cursor_attribute(*fact.a()) {
                bail!(
                    "legacy Comb commit {} contains unsupported fact on entity {id:X} attribute {:X}",
                    commit_hex(delta.commit),
                    fact.a()
                );
            }
            Ok(())
        };
        validate_fact(first)?;
        while facts.peek().is_some_and(|fact| fact.e() == &id) {
            validate_fact(facts.next().expect("peeked Comb fact"))?;
        }
    }
    Ok(())
}

fn is_cursor_attribute(attribute: Id) -> bool {
    attribute == metadata::created_at.id() || is_cursor_intrinsic_attribute(attribute)
}

fn is_cursor_intrinsic_attribute(attribute: Id) -> bool {
    attribute == metadata::tag.id()
        || attribute == cursor_stream.id()
        || attribute == cursor_persona.id()
        || attribute == cursor_position.id()
        || attribute == cursor_grain.id()
}

fn frontier(ids: impl IntoIterator<Item = Id>, graph: &BTreeMap<Id, BTreeSet<Id>>) -> BTreeSet<Id> {
    let ids: BTreeSet<_> = ids.into_iter().collect();
    ids.iter()
        .filter(|candidate| {
            !ids.iter()
                .any(|other| *candidate != other && is_ancestor(**candidate, *other, graph))
        })
        .copied()
        .collect()
}

fn is_ancestor(ancestor: Id, node: Id, graph: &BTreeMap<Id, BTreeSet<Id>>) -> bool {
    let mut pending: Vec<_> = graph
        .get(&node)
        .into_iter()
        .flat_map(|parents| parents.iter().copied())
        .collect();
    let mut seen = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if current == ancestor {
            return true;
        }
        if seen.insert(current) {
            pending.extend(
                graph
                    .get(&current)
                    .into_iter()
                    .flat_map(|parents| parents.iter().copied()),
            );
        }
    }
    false
}

/// One canonical Comb commit projected from one authored Repository delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CombCutoverCommit {
    pub source: LegacyCommitCoordinate,
    legacy_content: Fragment,
    legacy_metadata: Fragment,
    fragment: Fragment,
}

impl CombCutoverCommit {
    pub fn legacy_content(&self) -> &Fragment {
        &self.legacy_content
    }

    pub fn legacy_metadata(&self) -> &Fragment {
        &self.legacy_metadata
    }

    pub fn fragment(&self) -> &Fragment {
        &self.fragment
    }
}

/// A complete stopped-world projection into the separate Comb collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CombCutoverPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<CombCutoverCommit>,
    facts: TribleSet,
    aliases: BTreeMap<Id, Id>,
}

/// Conservation census for one legacy Comb cursor migration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CombMigrationReport {
    pub commits: usize,
    pub facts: usize,
    pub aliases: usize,
}

impl CombCutoverPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[CombCutoverCommit] {
        &self.commits
    }

    pub fn facts(&self) -> &TribleSet {
        &self.facts
    }

    /// Auditable in-memory correspondence from legacy cursor ids to canonical
    /// cursor snapshots. It is not asserted into the strict Comb scope.
    pub fn aliases(&self) -> &BTreeMap<Id, Id> {
        &self.aliases
    }

    /// Conservation census for this plan, in the same shape every other typed
    /// migration reports, so one caller can render all of them alike.
    pub fn report(&self) -> CombMigrationReport {
        CombMigrationReport {
            commits: self.commits.len(),
            facts: self.facts.len(),
            aliases: self.aliases.len(),
        }
    }

    pub fn verify(&self) -> Result<()> {
        let mut union = TribleSet::new();
        for commit in &self.commits {
            union += commit.fragment.facts().clone();
            let mut expected_metafacts = commit.legacy_content.metafacts().clone();
            expected_metafacts += commit.legacy_metadata.facts().clone();
            expected_metafacts += commit.legacy_metadata.metafacts().clone();
            if commit.fragment.metafacts() != &expected_metafacts {
                bail!(
                    "Comb output commit {} changes legacy semantic metadata",
                    hex::encode_upper(commit.source.commit.raw)
                );
            }
            let mut expected_blobs = commit.legacy_content.blobs().clone();
            expected_blobs.union(commit.legacy_metadata.blobs().clone());
            if commit.fragment.blobs() != &expected_blobs {
                bail!(
                    "Comb output commit {} changes resident metadata closure",
                    hex::encode_upper(commit.source.commit.raw)
                );
            }
        }
        if union != self.facts {
            bail!("Comb native COMMIT partition differs from its canonical plan");
        }
        comb::load_catalog(&union).context("validate complete planned Comb collection")?;
        Ok(())
    }
}

/// Plan the legacy Comb branch when present. An absent branch means replay had
/// no historical cursor state and is not a migration error.
pub fn plan_if_present(source: &FrozenSource) -> Result<Option<CombCutoverPlan>> {
    let Some(branch) = source.legacy_branch(schema::LEGACY_COMB_BRANCH_NAME)? else {
        return Ok(None);
    };
    transform_branch(source, &branch).map(Some)
}

/// Plan a required legacy Comb branch.
pub fn plan(source: &FrozenSource) -> Result<CombCutoverPlan> {
    plan_if_present(source)?.ok_or_else(|| anyhow!("frozen source has no legacy Comb branch"))
}

/// Publish canonical cursor snapshots through the fixed, separate Comb scope.
pub fn publish(
    source: &FrozenSource,
    plan: &CombCutoverPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Comb migration plan does not belong to this frozen source");
    }
    plan.verify()?;
    publish_fragments(
        target,
        key,
        schema::DEFAULT_COMB_SCOPE_ID,
        plan.commits.iter().map(|commit| commit.fragment.clone()),
    )
}

fn transform_branch(source: &FrozenSource, branch: &FrozenLegacyBranch) -> Result<CombCutoverPlan> {
    let projected = project_legacy_authored_commits(source, branch, validate_known_payloads)
        .context("project frozen Comb authored commits")?;
    let mut projected_by_commit: BTreeMap<_, _> = projected
        .into_iter()
        .map(|commit| (commit.source.commit.raw, commit))
        .collect();
    let plan = plan_legacy_comb(branch.deltas.iter().map(|delta| LegacyCombDelta {
        commit: delta.commit.raw,
        parents: delta.parents.iter().map(|parent| parent.raw).collect(),
        facts: delta.facts.clone(),
        authored: delta.is_authored(),
    }))?;

    let mut complete = TribleSet::new();
    let mut commits = Vec::with_capacity(projected_by_commit.len());
    for delta in branch.deltas.iter().filter(|delta| delta.is_authored()) {
        let projected = projected_by_commit
            .remove(&delta.commit.raw)
            .ok_or_else(|| {
                anyhow!(
                    "authored frozen Comb commit {} was not projected",
                    commit_hex(delta.commit.raw)
                )
            })?;
        let facts = plan
            .facts_by_commit
            .get(&delta.commit.raw)
            .cloned()
            .ok_or_else(|| anyhow!("authored Comb commit has no partition slot"))?;
        complete += facts.clone();
        let legacy_content = projected.content;
        let legacy_metadata = projected.metadata;
        let mut fragment = Fragment::from(facts);
        *fragment.metafacts_mut() += legacy_content.metafacts().clone();
        fragment.blobs_mut().union(legacy_content.blobs().clone());
        fragment.describe_with(legacy_metadata.clone());
        commits.push(CombCutoverCommit {
            source: projected.source,
            legacy_content,
            legacy_metadata,
            fragment,
        });
    }
    if !projected_by_commit.is_empty() {
        bail!("frozen Comb COMMIT partition did not consume every authored delta");
    }
    if complete != plan.facts {
        bail!("frozen Comb COMMIT content union differs from the global plan");
    }
    comb::load_catalog(&complete).context("validate planned Comb fragment")?;
    let cutover = CombCutoverPlan {
        source_pin: branch.pin_coordinate(),
        commits,
        facts: complete,
        aliases: plan.aliases,
    };
    cutover.verify()?;
    Ok(cutover)
}

fn validate_known_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts {
        if fact.a() == &metadata::name.id() || fact.a() == &metadata::description.id() {
            let handle = *fact.v::<Handle<UTF8String>>();
            let _: View<str> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read legacy Comb metadata text {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

fn commit_hex(commit: LegacyCommitId) -> String {
    hex::encode_upper(commit)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};

    use ed25519_dalek::SigningKey;
    use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace::core::repo::BlobStore;

    use super::*;
    use crate::collection_cutover::test_support::{TestBranchSpec, TestDeltaSpec, TestSourceSpec};
    use faculties::comb::CursorResolution;
    use faculties::storage::{initialize_signer, load_signer, open_pile_strict};

    fn point(seconds: f64) -> faculties::comb::IntervalValue {
        let at = hifitime::Epoch::from_tai_seconds(seconds);
        (at, at).try_to_inline().unwrap()
    }

    fn commit(byte: u8) -> LegacyCommitId {
        [byte; 32]
    }

    fn legacy(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn facts(fragment: Fragment) -> TribleSet {
        fragment.facts().clone()
    }

    fn cursor(
        id: Id,
        stream: &str,
        persona: &str,
        position: Option<f64>,
        grain: Option<&str>,
        observed: f64,
    ) -> TribleSet {
        let mut fragment = entity! { ExclusiveId::force_ref(&id) @
            metadata::tag: &kind_comb_cursor,
            cursor_stream: stream,
            cursor_persona: persona,
            metadata::created_at: point(observed),
        };
        if let Some(position) = position {
            fragment += entity! {
                ExclusiveId::force_ref(&id) @ cursor_position: point(position)
            };
        }
        if let Some(grain) = grain {
            fragment += entity! { ExclusiveId::force_ref(&id) @ cursor_grain: grain };
        }
        facts(fragment)
    }

    fn delta(
        byte: u8,
        parents: impl IntoIterator<Item = u8>,
        facts: TribleSet,
        authored: bool,
    ) -> LegacyCombDelta {
        LegacyCombDelta {
            commit: commit(byte),
            parents: parents.into_iter().map(commit).collect(),
            facts,
            authored,
        }
    }

    fn assert_disjoint(plan: &CombMigrationPlan) {
        let mut union = TribleSet::new();
        for facts in plan.facts_by_commit.values() {
            for fact in facts {
                assert!(
                    !union.contains(fact),
                    "canonical assertion has two commit owners"
                );
                union.insert(fact);
            }
        }
        assert_eq!(union, plan.facts);
    }

    #[test]
    fn eav_value_lookup_ignores_large_unrelated_population() {
        let entity = legacy(0x81);
        let first = inlineencodings::GenId::inline_from(legacy(0x82));
        let second = inlineencodings::GenId::inline_from(legacy(0x83));
        let mut all = TribleSet::new();
        all.insert(&Trible::force(
            ExclusiveId::force_ref(&entity),
            &metadata::tag.id(),
            &first,
        ));
        all.insert(&Trible::force(
            ExclusiveId::force_ref(&entity),
            &metadata::tag.id(),
            &second,
        ));
        all.insert(&Trible::force(
            ExclusiveId::force_ref(&entity),
            &cursor_position.id(),
            &point(1.0),
        ));

        for serial in 0u32..4096 {
            let mut raw = [0x91; 16];
            raw[12..].copy_from_slice(&serial.to_be_bytes());
            let noise = Id::new(raw).unwrap();
            all.insert(&Trible::force(
                ExclusiveId::force_ref(&noise),
                &metadata::tag.id(),
                &first,
            ));
        }

        assert_eq!(
            values(&all, entity, &metadata::tag),
            BTreeSet::from([first, second])
        );
        assert!(values(&all, legacy(0x84), &metadata::tag).is_empty());
    }

    #[test]
    fn repository_fork_is_visible_and_later_advance_rejoins_it() {
        let genesis = legacy(0x11);
        let left = legacy(0x12);
        let right = legacy(0x13);
        let joined = legacy(0x14);
        let deltas = vec![
            delta(
                1,
                [],
                cursor(
                    genesis,
                    "memory-replay",
                    "persona-a",
                    Some(0.0),
                    Some("2h"),
                    100.0,
                ),
                true,
            ),
            // Deliberately newer provenance on the left: it must not hide the right.
            delta(
                2,
                [1],
                cursor(
                    left,
                    "memory-replay",
                    "persona-a",
                    Some(10.0),
                    Some("2h"),
                    1_000.0,
                ),
                true,
            ),
            delta(
                3,
                [1],
                cursor(
                    right,
                    "memory-replay",
                    "persona-a",
                    Some(20.0),
                    Some("2h"),
                    2.0,
                ),
                true,
            ),
            delta(4, [2, 3], TribleSet::new(), false),
            delta(5, [4], TribleSet::new(), true),
        ];

        let fork_plan = plan_legacy_comb(deltas.clone()).unwrap();
        let fork = comb::load_catalog(&fork_plan.facts).unwrap();
        assert!(matches!(
            fork.resolution("memory-replay", "persona-a"),
            Some(CursorResolution::Forked(rows)) if rows.len() == 2
        ));
        assert!(!fork_plan.facts_by_commit.contains_key(&commit(4)));
        assert!(fork_plan.facts_by_commit[&commit(5)].is_empty());
        assert_disjoint(&fork_plan);

        let mut joined_deltas = deltas;
        joined_deltas.push(delta(
            6,
            [4],
            cursor(
                joined,
                "memory-replay",
                "persona-a",
                Some(30.0),
                Some("2h"),
                3.0,
            ),
            true,
        ));
        let joined_plan = plan_legacy_comb(joined_deltas.clone()).unwrap();
        let joined_catalog = comb::load_catalog(&joined_plan.facts).unwrap();
        let joined_id = joined_plan.aliases[&joined];
        assert_eq!(
            joined_catalog
                .resolution("memory-replay", "persona-a")
                .unwrap()
                .head_ids(),
            vec![joined_id]
        );
        assert_eq!(joined_catalog.cursors[&joined_id].predecessors.len(), 2);

        joined_deltas.reverse();
        assert_eq!(joined_plan, plan_legacy_comb(joined_deltas).unwrap());
    }

    #[test]
    fn predecessor_frontiers_are_separate_per_stream_and_persona() {
        let memory = legacy(0x21);
        let archive = legacy(0x22);
        let next_memory = legacy(0x23);
        let deltas = [
            delta(
                1,
                [],
                cursor(
                    memory,
                    "memory-replay",
                    "persona-a",
                    Some(1.0),
                    Some("2h"),
                    1.0,
                ),
                true,
            ),
            delta(
                2,
                [1],
                cursor(archive, "archive-replay", "persona-a", Some(2.0), None, 2.0),
                true,
            ),
            delta(
                3,
                [2],
                cursor(
                    next_memory,
                    "memory-replay",
                    "persona-a",
                    Some(3.0),
                    Some("2h"),
                    3.0,
                ),
                true,
            ),
        ];
        let plan = plan_legacy_comb(deltas).unwrap();
        let catalog = comb::load_catalog(&plan.facts).unwrap();
        let next = plan.aliases[&next_memory];
        assert_eq!(
            catalog.cursors[&next].predecessors,
            BTreeSet::from([plan.aliases[&memory]])
        );
        assert_eq!(
            catalog
                .resolution("archive-replay", "persona-a")
                .unwrap()
                .head_ids(),
            vec![plan.aliases[&archive]]
        );
    }

    #[test]
    fn late_identity_mutation_is_rejected_instead_of_clock_arbitrated() {
        let id = legacy(0x31);
        let amendment = facts(entity! {
            ExclusiveId::force_ref(&id) @ cursor_grain: "2h"
        });
        let error = plan_legacy_comb([
            delta(
                1,
                [],
                cursor(id, "memory-replay", "persona-a", Some(1.0), None, 1.0),
                true,
            ),
            delta(2, [1], amendment, true),
        ])
        .unwrap_err();
        assert!(format!("{error:#}").contains("mutates identity fields"));
    }

    #[test]
    fn v4_cutover_preserves_forks_and_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("comb.pile");
        let key = directory.path().join("comb.key");
        File::create(&pile_path).unwrap();
        initialize_signer(&pile_path, Some(&key)).unwrap();
        let genesis = TestDeltaSpec::authored(
            Fragment::from(cursor(
                legacy(0x41),
                "archive-replay",
                "persona-a",
                Some(0.0),
                None,
                1.0,
            )),
            "comb genesis message",
        )
        .with_metadata(entity! { metadata::description: "comb genesis provenance" });
        let left = TestDeltaSpec::authored(
            Fragment::from(cursor(
                legacy(0x42),
                "archive-replay",
                "persona-a",
                Some(10.0),
                None,
                100.0,
            )),
            "comb left message",
        )
        .with_metadata(entity! { metadata::description: "comb left provenance" });
        let right = TestDeltaSpec::authored(
            Fragment::from(cursor(
                legacy(0x43),
                "archive-replay",
                "persona-a",
                Some(20.0),
                None,
                2.0,
            )),
            "comb right message",
        )
        .with_metadata(entity! { metadata::description: "comb right provenance" })
        .with_parents([0]);
        let joined = TestDeltaSpec::authored(
            Fragment::from(cursor(
                legacy(0x44),
                "archive-replay",
                "persona-a",
                Some(30.0),
                None,
                3.0,
            )),
            "comb join message",
        )
        .with_metadata(entity! { metadata::description: "comb join provenance" });
        let frozen = TestSourceSpec::new(vec![TestBranchSpec::new(
            schema::LEGACY_COMB_BRANCH_NAME,
            Id::new([0xC4; 16]).unwrap(),
            SigningKey::from_bytes(&[0xC4; 32]),
            vec![genesis, left, right, TestDeltaSpec::merge([1, 2]), joined],
        )])
        .freeze(&pile_path)
        .unwrap();
        let cutover = plan(&frozen.source).unwrap();
        cutover.verify().unwrap();
        assert_eq!(cutover.commits().len(), 4);
        assert_eq!(cutover.aliases().len(), 4);
        let catalog = comb::load_catalog(cutover.facts()).unwrap();
        let resolution = catalog.resolution("archive-replay", "persona-a").unwrap();
        let joined = resolution.head_ids()[0];
        assert_eq!(catalog.cursors[&joined].predecessors.len(), 2);

        let first = publish(&frozen.source, &cutover, &pile_path, Some(&key)).unwrap();
        assert_eq!(first.len(), 4);
        let after_first = fs::metadata(&pile_path).unwrap().len();
        assert_eq!(
            publish(&frozen.source, &cutover, &pile_path, Some(&key)).unwrap(),
            first
        );
        assert_eq!(fs::metadata(&pile_path).unwrap().len(), after_first);

        let signer = load_signer(&pile_path, Some(&key)).unwrap();
        let pile = open_pile_strict(&pile_path).unwrap();
        let mut collection =
            faculties::collection_names::open(pile, schema::DEFAULT_COMB_SCOPE_ID, signer);
        assert_eq!(collection.materialize().unwrap(), *cutover.facts());
        let reader = collection.storage_mut().reader().unwrap();
        let metadata_facts: TribleSet = reader
            .get::<TribleSet, SimpleArchive>(first[0].metadata())
            .unwrap();
        validate_known_payloads(&reader, &metadata_facts).unwrap();
        collection.into_storage().close().unwrap();
    }
}
