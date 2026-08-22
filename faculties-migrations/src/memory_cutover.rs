//! Stopped-world projection of the historical Memory repository DAG.
//!
//! Legacy Memory used random entity ids and occasionally amended an existing
//! chunk in a later repository commit (notably `memory supersede`).  Projecting
//! only the final branch checkout would erase that authored transition.  This
//! planner instead follows the complete immutable repository DAG: every
//! authored delta yields one collection COMMIT, contentless repository merges
//! only combine planning frontiers, and an identity-changing amendment creates
//! a fresh intrinsic Memory successor over the visible predecessor antichain.
//!
//! Rebuildable search/embedding exhaust does not enter the canonical shadow,
//! but remains present in the exact preserved source facts. Legacy Memory ids
//! become exact aliases of their first complete intrinsic state. Cross-scope
//! Archive/Cognition ids are copied byte-for-byte: their own additive cutovers
//! preserve source identities, so Memory never guesses or rewrites them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::attribute::Attribute;
use triblespace::core::blob::Blob;
use triblespace::core::collection::{Collection, CollectionCommit};
use triblespace::core::inline::{Inline, InlineEncoding};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::*;
use triblespace_search::succinct::SuccinctBM25Blob;

use crate::collection_cutover::{project_legacy_authored_commits, FrozenLegacyBranch, FrozenSource, LegacyCommitCoordinate, LegacyPinCoordinate};
use faculties::storage::{load_signer, open_pile_strict};
use faculties::memory;
use faculties::schemas::embeddings::{self, Embedding768};
use faculties::schemas::memory::{
    self as schema, ctx, search_index, KIND_CHUNK_ID, KIND_RETRACTION, KIND_SEARCH_INDEX,
};

/// Historical pre-exact-TF Memory BM25 attribute.  The stopped-world reader
/// accepts it solely as rebuildable legacy exhaust; native Memory never emits
/// or queries it.
const LEGACY_SEARCH_INDEX_ATTRIBUTE: Id = id_hex!("3BAF1837E1A1128042A0582CF6D71CE0");

/// Content-addressed coordinate of one legacy repository commit.
pub type LegacyCommitId = [u8; 32];

/// Pure planner input. Ordering is deliberately non-semantic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyMemoryDelta {
    pub commit: LegacyCommitId,
    pub parents: BTreeSet<LegacyCommitId>,
    pub facts: TribleSet,
    pub authored: bool,
}

/// Which legacy foreign collection a Memory identity field names.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CrossScopeReferenceKind {
    CognitionExecResult,
    ArchiveMessage,
}

/// A foreign legacy id which cannot safely be rewritten by the Memory planner.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CrossScopeReference {
    pub legacy_chunk: Id,
    pub kind: CrossScopeReferenceKind,
    pub legacy_target: Id,
}

/// Complete canonical result and its COMMIT partition keyed by authored legacy commits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryMigrationPlan {
    pub facts: TribleSet,
    /// Contains every authored source commit, including empty partitions.
    pub facts_by_commit: BTreeMap<LegacyCommitId, TribleSet>,
    /// Exact aliases of legacy chunk ids to their first intrinsic state.
    pub aliases: BTreeMap<Id, Id>,
    pub cross_scope_references: BTreeSet<CrossScopeReference>,
    pub omitted_search_entities: BTreeSet<Id>,
    pub omitted_embedding_facts: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalChunk {
    content: memory::ChunkContent,
    start_at: memory::IntervalValue,
    end_at: memory::IntervalValue,
    lens: Option<memory::TextHandle>,
    references: BTreeSet<Id>,
    about_exec_result: Option<Id>,
    about_archive_message: Option<Id>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NodePayload {
    Chunk(CanonicalChunk),
    Retraction { reason: Option<memory::TextHandle> },
}

#[derive(Clone, Debug)]
struct LegacyChunk {
    content: memory::ChunkContent,
    start_at: memory::IntervalValue,
    end_at: memory::IntervalValue,
    lens: Option<memory::TextHandle>,
    references: BTreeSet<Id>,
    about_exec_result: Option<Id>,
    about_archive_message: Option<Id>,
    supersedes: BTreeSet<Id>,
    observed_at: BTreeSet<memory::IntervalValue>,
}

#[derive(Clone, Debug)]
struct LegacyRetraction {
    reason: Option<memory::TextHandle>,
    supersedes: BTreeSet<Id>,
    observed_at: BTreeSet<memory::IntervalValue>,
}

#[derive(Clone, Debug)]
enum LegacyNode {
    Chunk(LegacyChunk),
    Retraction(LegacyRetraction),
}

#[derive(Clone, Debug, Default)]
struct PlannerState {
    snapshot: TribleSet,
    /// Fork-visible canonical heads for each legacy Memory entity.
    current: BTreeMap<Id, BTreeSet<Id>>,
    /// The exact first intrinsic state named by a legacy chunk id.
    aliases: BTreeMap<Id, Id>,
}

#[derive(Default)]
struct PlannerContext {
    payloads: BTreeMap<Id, NodePayload>,
    predecessors: BTreeMap<Id, BTreeSet<Id>>,
    /// Exact reachability answers already demanded while maintaining canonical
    /// head antichains. Canonical predecessor sets are immutable, so cached
    /// answers remain valid as unrelated nodes are appended to the DAG.
    ancestor_cache: BTreeMap<(Id, Id), bool>,
    aliases: BTreeMap<Id, Id>,
    raw_by_commit: BTreeMap<LegacyCommitId, TribleSet>,
    cross_scope_references: BTreeSet<CrossScopeReference>,
    omitted_search_entities: BTreeSet<Id>,
    omitted_embedding_facts: usize,
}

#[derive(Default, Debug, Eq, PartialEq)]
struct PlannerProfile {
    /// State copies forced by a genuine repository fork. Linear history moves
    /// its one state forward instead.
    fork_state_clones: usize,
    /// Repository states retained because a future child still needs them.
    peak_retained_states: usize,
}

struct Topology {
    ordered: Vec<LegacyCommitId>,
    /// Number of children which have not consumed each commit's state yet.
    remaining_uses: BTreeMap<LegacyCommitId, usize>,
}

#[derive(Default)]
struct DeltaEffect {
    new_intrinsic: bool,
    new_observations: BTreeSet<memory::IntervalValue>,
}

/// Give every canonical shadow fact one deterministic authored owner while
/// retaining explicit empty authored commits.  Source coordinates are already
/// ordered by the frozen branch's content-addressed commit identity.
fn disjoint_first_witness_partition<K: Ord>(
    raw: BTreeMap<K, TribleSet>,
) -> (TribleSet, BTreeMap<K, TribleSet>) {
    let mut complete = TribleSet::new();
    let mut partition = BTreeMap::new();
    for (source, facts) in raw {
        let unique = facts.difference(&complete);
        complete.union(unique.clone());
        partition.insert(source, unique);
    }
    (complete, partition)
}

/// Plan the whole legacy Memory repository DAG without reading a clock, signer,
/// destination, mutable pile, or branch tip outside the supplied snapshot.
pub fn plan_legacy_memory(
    deltas: impl IntoIterator<Item = LegacyMemoryDelta>,
) -> Result<MemoryMigrationPlan> {
    plan_legacy_memory_profiled(deltas).map(|(plan, _)| plan)
}

fn plan_legacy_memory_profiled(
    deltas: impl IntoIterator<Item = LegacyMemoryDelta>,
) -> Result<(MemoryMigrationPlan, PlannerProfile)> {
    let deltas: Vec<_> = deltas.into_iter().collect();
    let Topology {
        ordered,
        mut remaining_uses,
    } = topological(&deltas)?;
    let mut context = PlannerContext::default();
    for delta in &deltas {
        if delta.authored {
            context.raw_by_commit.entry(delta.commit).or_default();
        } else if !delta.facts.is_empty() {
            bail!(
                "contentless Memory merge {} carries authored facts",
                commit_hex(delta.commit)
            );
        }
    }

    // Own deltas by coordinate so their raw fact roots are released as soon as
    // their commit is planned. Keeping the input vector beside every cumulative
    // snapshot retained a second complete repository for the whole run.
    let mut by_commit: BTreeMap<_, _> = deltas
        .into_iter()
        .map(|delta| (delta.commit, delta))
        .collect();
    let mut states = BTreeMap::<LegacyCommitId, PlannerState>::new();
    let mut profile = PlannerProfile::default();
    for commit in ordered {
        let delta = by_commit
            .remove(&commit)
            .expect("topology contains every Memory delta exactly once");
        let mut state = merge_parent_states(
            &delta,
            &mut states,
            &mut remaining_uses,
            &mut context,
            &mut profile,
        )?;
        let effects = delta_effects(&state.snapshot, &delta.facts);
        state.snapshot += delta.facts.clone();
        validate_delta_shape(&state.snapshot, &delta, &mut context)?;
        if delta.authored {
            project_authored_delta(delta.commit, effects, &mut state, &mut context)
                .with_context(|| format!("project legacy Memory commit {}", commit_hex(commit)))?;
        }
        if remaining_uses[&commit] > 0 {
            states.insert(commit, state);
            profile.peak_retained_states = profile.peak_retained_states.max(states.len());
        }
    }
    debug_assert!(states.is_empty());
    debug_assert!(by_commit.is_empty());
    debug_assert!(remaining_uses.values().all(|uses| *uses == 0));

    let (facts, facts_by_commit) = disjoint_first_witness_partition(context.raw_by_commit);
    memory::load_catalog(&facts).context("validate globally planned Memory revision DAG")?;

    let plan = MemoryMigrationPlan {
        facts,
        facts_by_commit,
        aliases: context.aliases,
        cross_scope_references: context.cross_scope_references,
        omitted_search_entities: context.omitted_search_entities,
        omitted_embedding_facts: context.omitted_embedding_facts,
    };
    Ok((plan, profile))
}

fn topological(deltas: &[LegacyMemoryDelta]) -> Result<Topology> {
    let mut by_commit = BTreeMap::new();
    for delta in deltas {
        if by_commit.insert(delta.commit, delta).is_some() {
            bail!(
                "legacy Memory DAG repeats commit {}",
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
                    "legacy Memory commit {} names parent {} outside the captured DAG",
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
            let count = remaining.get_mut(child).expect("known Memory child");
            *count -= 1;
            if *count == 0 {
                ready.insert(*child);
            }
        }
    }
    if ordered.len() != deltas.len() {
        bail!("legacy Memory repository ancestry contains a cycle");
    }
    let remaining_uses = by_commit
        .keys()
        .map(|commit| {
            (
                *commit,
                children.get(commit).map(BTreeSet::len).unwrap_or_default(),
            )
        })
        .collect();
    Ok(Topology {
        ordered,
        remaining_uses,
    })
}

fn merge_parent_states(
    delta: &LegacyMemoryDelta,
    states: &mut BTreeMap<LegacyCommitId, PlannerState>,
    remaining_uses: &mut BTreeMap<LegacyCommitId, usize>,
    context: &mut PlannerContext,
    profile: &mut PlannerProfile,
) -> Result<PlannerState> {
    let mut parents = Vec::with_capacity(delta.parents.len());
    for parent in &delta.parents {
        let uses = remaining_uses.get_mut(parent).ok_or_else(|| {
            anyhow!(
                "missing use count for Memory parent {}",
                commit_hex(*parent)
            )
        })?;
        if *uses == 0 {
            bail!(
                "legacy Memory parent {} was consumed before child {}",
                commit_hex(*parent),
                commit_hex(delta.commit)
            );
        }
        *uses -= 1;
        let state = if *uses == 0 {
            states.remove(parent)
        } else {
            profile.fork_state_clones += 1;
            states.get(parent).cloned()
        }
        .ok_or_else(|| {
            anyhow!(
                "legacy Memory parent {} was not planned before child {}",
                commit_hex(*parent),
                commit_hex(delta.commit)
            )
        })?;
        parents.push(state);
    }

    let mut parents = parents.into_iter();
    let mut merged = parents.next().unwrap_or_default();
    for state in parents {
        merged.snapshot += state.snapshot;
        for (legacy, heads) in state.current {
            let current = merged.current.entry(legacy).or_default();
            merge_frontier(
                current,
                heads,
                &context.predecessors,
                &mut context.ancestor_cache,
            );
        }
        for (legacy, canonical) in state.aliases {
            if let Some(previous) = merged.aliases.insert(legacy, canonical) {
                if previous != canonical {
                    bail!("legacy Memory alias {legacy:X} diverges across repository parents");
                }
            }
        }
    }
    Ok(merged)
}

fn delta_effects(parent: &TribleSet, facts: &TribleSet) -> BTreeMap<Id, DeltaEffect> {
    let mut effects = BTreeMap::<Id, DeltaEffect>::new();
    for fact in facts {
        let effect = effects.entry(*fact.e()).or_default();
        if is_memory_intrinsic_attribute(*fact.a()) && !parent.contains(fact) {
            effect.new_intrinsic = true;
        }
        if fact.a() == &metadata::created_at.id() {
            effect
                .new_observations
                .insert(*fact.v::<inlineencodings::NsTAIInterval>());
        }
    }
    effects
}

fn project_authored_delta(
    commit: LegacyCommitId,
    effects: BTreeMap<Id, DeltaEffect>,
    state: &mut PlannerState,
    context: &mut PlannerContext,
) -> Result<()> {
    let mut pending = BTreeMap::new();
    for (legacy, effect) in effects {
        let Some(node) = parse_legacy_node(&state.snapshot, legacy)? else {
            continue;
        };
        pending.insert(
            legacy,
            (node, effect.new_intrinsic, effect.new_observations),
        );
    }
    while !pending.is_empty() {
        let ready: Vec<Id> = pending
            .iter()
            .filter_map(|(&legacy, (node, _, _))| node_ready(node, state).then_some(legacy))
            .collect();
        if ready.is_empty() {
            bail!(
                "legacy Memory commit {} has unresolved or cyclic intra-delta references on {}",
                commit_hex(commit),
                pending
                    .keys()
                    .map(|id| format!("{id:X}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        for legacy in ready {
            let (node, new_intrinsic, new_observations) =
                pending.remove(&legacy).expect("ready Memory node");
            project_node(
                commit,
                legacy,
                node,
                new_intrinsic,
                new_observations,
                state,
                context,
            )?;
        }
    }
    Ok(())
}

fn node_ready(node: &LegacyNode, state: &PlannerState) -> bool {
    let supersedes_ready = |targets: &BTreeSet<Id>| {
        targets.iter().all(|target| {
            state
                .current
                .get(target)
                .is_some_and(|heads| !heads.is_empty())
        })
    };
    match node {
        LegacyNode::Chunk(row) => {
            row.references
                .iter()
                .all(|target| state.aliases.contains_key(target))
                && supersedes_ready(&row.supersedes)
        }
        LegacyNode::Retraction(row) => supersedes_ready(&row.supersedes),
    }
}

#[allow(clippy::too_many_arguments)]
fn project_node(
    commit: LegacyCommitId,
    legacy: Id,
    node: LegacyNode,
    new_intrinsic: bool,
    new_observations: BTreeSet<memory::IntervalValue>,
    state: &mut PlannerState,
    context: &mut PlannerContext,
) -> Result<()> {
    let current = state.current.get(&legacy).cloned().unwrap_or_default();
    let (payload, legacy_supersedes, all_observations, is_chunk) = match node {
        LegacyNode::Chunk(row) => {
            let mut references = BTreeSet::new();
            for target in &row.references {
                references.insert(*state.aliases.get(target).ok_or_else(|| {
                    anyhow!(
                        "legacy Memory chunk {legacy:X} references chunk {target:X} without an exact visible alias"
                    )
                })?);
            }
            if let Some(target) = row.about_exec_result {
                context.cross_scope_references.insert(CrossScopeReference {
                    legacy_chunk: legacy,
                    kind: CrossScopeReferenceKind::CognitionExecResult,
                    legacy_target: target,
                });
            }
            if let Some(target) = row.about_archive_message {
                context.cross_scope_references.insert(CrossScopeReference {
                    legacy_chunk: legacy,
                    kind: CrossScopeReferenceKind::ArchiveMessage,
                    legacy_target: target,
                });
            }
            (
                NodePayload::Chunk(CanonicalChunk {
                    content: row.content,
                    start_at: row.start_at,
                    end_at: row.end_at,
                    lens: row.lens,
                    references,
                    about_exec_result: row.about_exec_result,
                    about_archive_message: row.about_archive_message,
                }),
                row.supersedes,
                row.observed_at,
                true,
            )
        }
        LegacyNode::Retraction(row) => (
            NodePayload::Retraction { reason: row.reason },
            row.supersedes,
            row.observed_at,
            false,
        ),
    };

    let mut target_heads = BTreeSet::new();
    for target in legacy_supersedes {
        if target == legacy {
            bail!("legacy Memory entity {legacy:X} supersedes itself");
        }
        let heads = state.current.get(&target).ok_or_else(|| {
            anyhow!(
                "legacy Memory entity {legacy:X} supersedes {target:X} without a visible canonical state"
            )
        })?;
        merge_frontier(
            &mut target_heads,
            heads.iter().copied(),
            &context.predecessors,
            &mut context.ancestor_cache,
        );
    }

    let create = if current.is_empty() {
        true
    } else if new_intrinsic {
        let payload_changed = current
            .iter()
            .any(|head| context.payloads.get(head) != Some(&payload));
        let uncovered_history = target_heads.iter().any(|target| {
            !current.iter().any(|head| {
                head == target
                    || is_ancestor(
                        *target,
                        *head,
                        &context.predecessors,
                        &mut context.ancestor_cache,
                    )
            })
        });
        payload_changed || uncovered_history
    } else {
        false
    };

    if create {
        let predecessors = if current.is_empty() {
            target_heads
        } else {
            let mut predecessors = current.clone();
            merge_frontier(
                &mut predecessors,
                target_heads,
                &context.predecessors,
                &mut context.ancestor_cache,
            );
            predecessors
        };
        let observations = if current.is_empty() {
            all_observations
        } else {
            new_observations
        };
        let alias = (current.is_empty() && is_chunk).then_some(legacy);
        let (fragment, canonical) = canonical_record(&payload, &predecessors, &observations, alias);
        register_node(canonical, payload, predecessors, context)?;
        *state.current.entry(legacy).or_default() = BTreeSet::from([canonical]);
        if let Some(alias) = alias {
            if let Some(previous) = state.aliases.insert(alias, canonical) {
                if previous != canonical {
                    bail!("legacy Memory alias {alias:X} changed intrinsic target");
                }
            }
            if let Some(previous) = context.aliases.insert(alias, canonical) {
                if previous != canonical {
                    bail!("legacy Memory alias {alias:X} changed intrinsic target");
                }
            }
        }
        *context
            .raw_by_commit
            .get_mut(&commit)
            .expect("authored commit") += fragment;
    } else if !new_observations.is_empty() {
        if current.len() != 1 {
            bail!(
                "legacy Memory entity {legacy:X} receives an observation while forked across {} states",
                current.len()
            );
        }
        let canonical = *current.first().expect("one current state");
        let mut annotations = Fragment::empty();
        for observed in new_observations {
            annotations += entity! {
                ExclusiveId::force_ref(&canonical) @ metadata::created_at: observed
            };
        }
        *context
            .raw_by_commit
            .get_mut(&commit)
            .expect("authored commit") += annotations;
    }
    Ok(())
}

fn canonical_record(
    payload: &NodePayload,
    predecessors: &BTreeSet<Id>,
    observations: &BTreeSet<memory::IntervalValue>,
    alias: Option<Id>,
) -> (Fragment, Id) {
    let mut fragment = match payload {
        NodePayload::Chunk(row) => {
            let summary = match row.content {
                memory::ChunkContent::Text(handle) => Some(handle),
                memory::ChunkContent::Image(_) => None,
            };
            let image = match row.content {
                memory::ChunkContent::Text(_) => None,
                memory::ChunkContent::Image(handle) => Some(handle),
            };
            entity! {
                metadata::tag: &KIND_CHUNK_ID,
                ctx::summary?: summary.as_ref(),
                ctx::image?: image.as_ref(),
                ctx::start_at: row.start_at,
                ctx::end_at: row.end_at,
                ctx::lens?: row.lens.as_ref(),
                ctx::reference*: row.references.iter(),
                ctx::about_exec_result?: row.about_exec_result.as_ref(),
                ctx::about_archive_message?: row.about_archive_message.as_ref(),
                metadata::supersedes*: predecessors.iter(),
            }
        }
        NodePayload::Retraction { reason } => entity! {
            metadata::tag: &KIND_RETRACTION,
            ctx::summary?: reason.as_ref(),
            metadata::supersedes*: predecessors.iter(),
        },
    };
    let id = fragment
        .root()
        .expect("canonical Memory record has one intrinsic root");
    for observed in observations {
        fragment += entity! { ExclusiveId::force_ref(&id) @ metadata::created_at: observed };
    }
    if let Some(alias) = alias {
        let alias = inlineencodings::GenId::inline_from(alias);
        fragment += entity! { ExclusiveId::force_ref(&id) @ metadata::anchor: alias };
    }
    (fragment, id)
}

fn register_node(
    id: Id,
    payload: NodePayload,
    predecessors: BTreeSet<Id>,
    context: &mut PlannerContext,
) -> Result<()> {
    if let Some(previous) = context.payloads.insert(id, payload.clone()) {
        if previous != payload || context.predecessors.get(&id) != Some(&predecessors) {
            bail!("canonical Memory id {id:X} was rebuilt with different semantics");
        }
    }
    context.predecessors.insert(id, predecessors);
    Ok(())
}

/// Join canonical head antichains by retaining only their maximal elements.
/// Insertion order cannot affect the result: every candidate is either below
/// an existing maximal element, or removes exactly the elements below it.
fn merge_frontier(
    frontier: &mut BTreeSet<Id>,
    candidates: impl IntoIterator<Item = Id>,
    graph: &BTreeMap<Id, BTreeSet<Id>>,
    cache: &mut BTreeMap<(Id, Id), bool>,
) {
    for candidate in candidates {
        if frontier.contains(&candidate) {
            continue;
        }
        let existing: Vec<_> = frontier.iter().copied().collect();
        if existing
            .iter()
            .any(|head| is_ancestor(candidate, *head, graph, cache))
        {
            continue;
        }
        for head in existing {
            if is_ancestor(head, candidate, graph, cache) {
                frontier.remove(&head);
            }
        }
        frontier.insert(candidate);
    }
}

fn is_ancestor(
    ancestor: Id,
    node: Id,
    graph: &BTreeMap<Id, BTreeSet<Id>>,
    cache: &mut BTreeMap<(Id, Id), bool>,
) -> bool {
    if ancestor == node {
        return false;
    }
    if let Some(answer) = cache.get(&(ancestor, node)) {
        return *answer;
    }
    let mut pending: Vec<_> = graph
        .get(&node)
        .into_iter()
        .flat_map(|parents| parents.iter().copied())
        .collect();
    let mut seen = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if current == ancestor {
            cache.insert((ancestor, node), true);
            return true;
        }
        if seen.insert(current) {
            if let Some(answer) = cache.get(&(ancestor, current)) {
                if *answer {
                    cache.insert((ancestor, node), true);
                    return true;
                }
                continue;
            }
            pending.extend(
                graph
                    .get(&current)
                    .into_iter()
                    .flat_map(|parents| parents.iter().copied()),
            );
        }
    }
    cache.insert((ancestor, node), false);
    false
}

fn parse_legacy_node(space: &TribleSet, id: Id) -> Result<Option<LegacyNode>> {
    let tags = values(space, id, &metadata::tag);
    let supersedes: BTreeSet<Id> = values(space, id, &ctx::supersedes)
        .into_iter()
        .map(|value| value.try_from_inline().expect("GenId decodes infallibly"))
        .collect();
    if tags.contains(&inlineencodings::GenId::inline_from(KIND_CHUNK_ID)) {
        if tags.len() != 1 {
            bail!("legacy Memory chunk {id:X} has competing kind tags");
        }
        let summaries = values(space, id, &ctx::summary);
        let images = values(space, id, &ctx::image);
        let content = match (summaries.len(), images.len()) {
            (1, 0) => memory::ChunkContent::Text(*summaries.first().expect("one summary")),
            (0, 1) => memory::ChunkContent::Image(*images.first().expect("one image")),
            (summary_count, image_count) => bail!(
                "legacy Memory chunk {id:X} has {summary_count} summaries and {image_count} images"
            ),
        };
        let mut references: BTreeSet<Id> = values(space, id, &ctx::reference)
            .into_iter()
            .map(|value| value.try_from_inline().expect("GenId decodes infallibly"))
            .collect();
        references.extend(values(space, id, &ctx::left).into_iter().map(|value| {
            value
                .try_from_inline::<Id>()
                .expect("GenId decodes infallibly")
        }));
        references.extend(values(space, id, &ctx::right).into_iter().map(|value| {
            value
                .try_from_inline::<Id>()
                .expect("GenId decodes infallibly")
        }));
        return Ok(Some(LegacyNode::Chunk(LegacyChunk {
            content,
            start_at: one_required(values(space, id, &ctx::start_at), id, "ctx::start_at")?,
            end_at: one_required(values(space, id, &ctx::end_at), id, "ctx::end_at")?,
            lens: one(values(space, id, &ctx::lens), id, "ctx::lens")?,
            references,
            about_exec_result: one(
                values(space, id, &ctx::about_exec_result),
                id,
                "ctx::about_exec_result",
            )?
            .map(|value| value.try_from_inline().expect("GenId decodes infallibly")),
            about_archive_message: one(
                values(space, id, &ctx::about_archive_message),
                id,
                "ctx::about_archive_message",
            )?
            .map(|value| value.try_from_inline().expect("GenId decodes infallibly")),
            supersedes,
            observed_at: values(space, id, &metadata::created_at),
        })));
    }
    let typed_retraction = tags.contains(&inlineencodings::GenId::inline_from(KIND_RETRACTION));
    // Before Memory gained an explicit retraction kind, a redaction was
    // represented by a fresh otherwise-untyped entity carrying only the
    // `supersedes` relation (and, in principle, its ordinary retraction
    // annotations). The legacy reader intentionally interpreted every such
    // edge, independent of the source entity's tag. Preserve that semantic
    // act by projecting the old marker to a canonical typed retraction.
    let implicit_retraction = tags.is_empty() && !supersedes.is_empty();
    if typed_retraction || implicit_retraction {
        if typed_retraction && tags.len() != 1 {
            bail!("legacy Memory retraction {id:X} has competing kind tags");
        }
        if supersedes.is_empty() {
            bail!("legacy Memory retraction {id:X} supersedes no chunk");
        }
        return Ok(Some(LegacyNode::Retraction(LegacyRetraction {
            reason: one(values(space, id, &ctx::summary), id, "retraction reason")?,
            supersedes,
            observed_at: values(space, id, &metadata::created_at),
        })));
    }
    Ok(None)
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
            "legacy Memory entity {entity:X} has {} values for {field}",
            values.len()
        );
    }
    Ok(values.pop_first())
}

fn one_required<T: Ord>(values: BTreeSet<T>, entity: Id, field: &str) -> Result<T> {
    one(values, entity, field)?
        .ok_or_else(|| anyhow!("legacy Memory entity {entity:X} is missing {field}"))
}

fn validate_delta_shape(
    snapshot: &TribleSet,
    delta: &LegacyMemoryDelta,
    context: &mut PlannerContext,
) -> Result<()> {
    // TribleSet iteration is EAV ordered, so an entity's delta facts are
    // contiguous and share one stopped-world classification lookup.
    let mut facts = delta.facts.iter().peekable();
    while let Some(first) = facts.next() {
        let id = *first.e();
        let tags = values(snapshot, id, &metadata::tag);
        let chunk = tags.contains(&inlineencodings::GenId::inline_from(KIND_CHUNK_ID));
        let retraction = tags.contains(&inlineencodings::GenId::inline_from(KIND_RETRACTION));
        let implicit_retraction = tags.is_empty()
            && exists!(
                (target: Id),
                pattern!(snapshot, [{ id @ ctx::supersedes: ?target }])
            );
        let search = tags.contains(&inlineencodings::GenId::inline_from(KIND_SEARCH_INDEX));
        if search {
            context.omitted_search_entities.insert(id);
        }

        let mut validate_fact = |fact: &Trible| -> Result<()> {
            let allowed = if chunk {
                is_chunk_attribute(*fact.a()) || fact.a() == &embeddings::attr::embedding.id()
            } else if retraction || implicit_retraction {
                is_retraction_attribute(*fact.a())
            } else if search {
                fact.a() == &metadata::tag.id()
                    || fact.a() == &search_index::index.id()
                    || fact.a() == &LEGACY_SEARCH_INDEX_ATTRIBUTE
                    || fact.a() == &search_index::indexed_at.id()
            } else {
                false
            };
            if !allowed {
                bail!(
                    "legacy Memory commit {} contains unsupported fact on entity {id:X} attribute {:X}",
                    commit_hex(delta.commit),
                    fact.a()
                );
            }
            if chunk && fact.a() == &embeddings::attr::embedding.id() {
                context.omitted_embedding_facts += 1;
            }
            Ok(())
        };
        validate_fact(first)?;
        while facts.peek().is_some_and(|fact| fact.e() == &id) {
            validate_fact(facts.next().expect("peeked Memory fact"))?;
        }
    }
    Ok(())
}

fn is_chunk_attribute(attribute: Id) -> bool {
    attribute == metadata::tag.id()
        || attribute == metadata::created_at.id()
        || is_memory_intrinsic_attribute(attribute)
}

fn is_retraction_attribute(attribute: Id) -> bool {
    attribute == metadata::tag.id()
        || attribute == metadata::created_at.id()
        || attribute == ctx::summary.id()
        || attribute == ctx::supersedes.id()
}

fn is_memory_intrinsic_attribute(attribute: Id) -> bool {
    attribute == metadata::tag.id()
        || attribute == ctx::summary.id()
        || attribute == ctx::image.id()
        || attribute == ctx::start_at.id()
        || attribute == ctx::end_at.id()
        || attribute == ctx::lens.id()
        || attribute == ctx::reference.id()
        || attribute == ctx::left.id()
        || attribute == ctx::right.id()
        || attribute == ctx::about_exec_result.id()
        || attribute == ctx::about_archive_message.id()
        || attribute == ctx::supersedes.id()
}

fn validate_legacy_memory_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts {
        let atlas_text = fact.a() == &metadata::name.id()
            || fact.a() == &metadata::description.id()
            || fact.a() == &metadata::iri.id()
            || fact.a() == &metadata::source.id()
            || fact.a() == &metadata::source_module.id();
        if atlas_text {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::UTF8String>>();
            let _: anybytes::View<str> = reader.get(handle).with_context(|| {
                format!(
                    "read legacy Memory metadata text {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        } else if fact.a() == &metadata::value_formatter.id() {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::WasmCode>>();
            let _: Blob<blobencodings::WasmCode> = reader.get(handle).with_context(|| {
                format!(
                    "read legacy Memory metadata formatter {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        } else if fact.a() == &ctx::summary.id() || fact.a() == &ctx::lens.id() {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::UTF8String>>();
            let _: anybytes::View<str> = reader.get(handle).with_context(|| {
                format!("read legacy Memory text {}", hex::encode_upper(handle.raw))
            })?;
        } else if fact.a() == &ctx::image.id() {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::RawBytes>>();
            let _: anybytes::Bytes = reader.get(handle).with_context(|| {
                format!("read legacy Memory image {}", hex::encode_upper(handle.raw))
            })?;
        } else if fact.a() == &embeddings::attr::embedding.id() {
            let handle = *fact.v::<inlineencodings::Handle<Embedding768>>();
            let _: anybytes::View<[f32]> = reader.get(handle).with_context(|| {
                format!(
                    "read legacy Memory embedding {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        } else if fact.a() == &search_index::index.id()
            || fact.a() == &LEGACY_SEARCH_INDEX_ATTRIBUTE
        {
            let handle = *fact.v::<inlineencodings::Handle<SuccinctBM25Blob>>();
            let _: Blob<SuccinctBM25Blob> = reader.get(handle).with_context(|| {
                format!(
                    "read legacy Memory search index {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

fn attach_memory_payloads(reader: &PileReader, fragment: &mut Fragment) -> Result<()> {
    let facts = fragment.facts().clone();
    let text: BTreeSet<memory::TextHandle> = facts
        .iter()
        .filter(|fact| fact.a() == &ctx::summary.id() || fact.a() == &ctx::lens.id())
        .map(|fact| *fact.v::<inlineencodings::Handle<blobencodings::UTF8String>>())
        .collect();
    for handle in text {
        let blob: Blob<blobencodings::UTF8String> = reader.get(handle).with_context(|| {
            format!(
                "attach planned Memory text {}",
                hex::encode_upper(handle.raw)
            )
        })?;
        let actual = fragment.blobs_mut().insert(blob);
        if actual != handle {
            bail!("planned Memory text changed content identity");
        }
    }
    let images: BTreeSet<memory::ImageHandle> = facts
        .iter()
        .filter(|fact| fact.a() == &ctx::image.id())
        .map(|fact| *fact.v::<inlineencodings::Handle<blobencodings::RawBytes>>())
        .collect();
    for handle in images {
        let blob: Blob<blobencodings::RawBytes> = reader.get(handle).with_context(|| {
            format!(
                "attach planned Memory image {}",
                hex::encode_upper(handle.raw)
            )
        })?;
        let actual = fragment.blobs_mut().insert(blob);
        if actual != handle {
            bail!("planned Memory image changed content identity");
        }
    }
    Ok(())
}

/// One native commit projected from one exact authored legacy commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryCollectionMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
}

/// Conservation and normalization summary for a stopped-world migration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MemoryCollectionMigrationReport {
    pub authored_commits: usize,
    pub preserved_facts: usize,
    pub canonical_nodes: usize,
    pub canonical_facts: usize,
    pub output_facts: usize,
    pub legacy_aliases: usize,
    pub cross_scope_references: usize,
    pub omitted_search_entities: usize,
    pub omitted_embedding_facts: usize,
}

/// Exact legacy commits plus additive canonical Memory shadows, ready for
/// native collection publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryCollectionMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<MemoryCollectionMigrationCommit>,
    original: TribleSet,
    canonical: TribleSet,
    report: MemoryCollectionMigrationReport,
}

impl MemoryCollectionMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[MemoryCollectionMigrationCommit] {
        &self.commits
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    pub fn canonical_facts(&self) -> &TribleSet {
        &self.canonical
    }

    pub const fn report(&self) -> &MemoryCollectionMigrationReport {
        &self.report
    }

    pub fn materialized_facts(&self) -> TribleSet {
        let mut facts = TribleSet::new();
        for commit in &self.commits {
            facts += commit.fragment.facts().clone();
        }
        facts
    }

    pub fn verify_conservation(&self) -> Result<()> {
        let mut expected = self.original.clone();
        expected += self.canonical.clone();
        if self.materialized_facts() != expected {
            bail!("planned Memory collection is not original facts union canonical shadows");
        }
        Ok(())
    }

    fn validate(&self, reader: &PileReader) -> Result<()> {
        self.verify_conservation()?;
        let mut complete = Fragment::empty();
        for commit in &self.commits {
            complete += commit.fragment.clone();
        }
        memory::validate_candidate(reader, &TribleSet::new(), &complete)
            .context("validate planned Memory collection and attachments")?;
        Ok(())
    }
}

/// Plan the complete named legacy Memory branch without mutating its pile.
///
/// Every source-authored commit is retained exactly, including its metadata
/// and resident blob closure.  Canonical intrinsic revision records are
/// additive shadows assigned to the same authored coordinate; original entity
/// ids are never recomputed or replaced.  Archive/Cognition targets remain
/// byte-identical because their own additive migrations preserve those ids.
pub fn plan(source: &FrozenSource) -> Result<MemoryCollectionMigrationPlan> {
    let branch = source
        .legacy_branch(schema::LEGACY_MEMORY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Memory branch"))?;
    plan_branch(source, &branch)
}

fn plan_branch(
    source: &FrozenSource,
    branch: &FrozenLegacyBranch,
) -> Result<MemoryCollectionMigrationPlan> {
    let mut projected =
        project_legacy_authored_commits(source, branch, validate_legacy_memory_payloads)
            .context("project frozen Memory authored commits")?;
    projected.sort_unstable_by_key(|commit| commit.source);

    let canonical_plan = plan_legacy_memory(branch.deltas.iter().map(|delta| LegacyMemoryDelta {
        commit: delta.commit.raw,
        parents: delta.parents.iter().map(|parent| parent.raw).collect(),
        facts: delta.facts.clone(),
        authored: delta.is_authored(),
    }))?;

    let source_pin = branch.pin_coordinate();
    let mut original = TribleSet::new();
    let mut commits = Vec::with_capacity(projected.len());
    let mut seen = BTreeSet::new();
    for mut projected in projected {
        if projected.source.branch != source_pin.id || projected.source.pin != source_pin.value {
            bail!("Memory authored commits do not belong to one frozen branch pin");
        }
        if !seen.insert(projected.source) {
            bail!(
                "Memory migration input repeats legacy authored commit {}",
                hex::encode_upper(projected.source.commit.raw)
            );
        }
        original += projected.content.facts().clone();

        let shadow_facts = canonical_plan
            .facts_by_commit
            .get(&projected.source.commit.raw)
            .cloned()
            .ok_or_else(|| anyhow!("authored Memory commit has no canonical partition slot"))?;
        let mut shadows = Fragment::from(shadow_facts);
        attach_memory_payloads(source.reader(), &mut shadows)?;
        projected.content += shadows;
        projected.content.describe_with(projected.metadata);
        commits.push(MemoryCollectionMigrationCommit {
            source: projected.source,
            fragment: projected.content,
        });
    }

    if commits.len() != canonical_plan.facts_by_commit.len() {
        bail!("canonical Memory partition does not name every authored source commit");
    }

    let output_facts = {
        let mut facts = TribleSet::new();
        for commit in &commits {
            facts += commit.fragment.facts().clone();
        }
        facts.len()
    };
    let canonical_catalog = memory::load_catalog(&canonical_plan.facts)
        .context("validate globally planned intrinsic Memory DAG")?;
    let plan = MemoryCollectionMigrationPlan {
        source_pin,
        report: MemoryCollectionMigrationReport {
            authored_commits: commits.len(),
            preserved_facts: original.len(),
            canonical_nodes: canonical_catalog.node_ids().len(),
            canonical_facts: canonical_plan.facts.len(),
            output_facts,
            legacy_aliases: canonical_plan.aliases.len(),
            cross_scope_references: canonical_plan.cross_scope_references.len(),
            omitted_search_entities: canonical_plan.omitted_search_entities.len(),
            omitted_embedding_facts: canonical_plan.omitted_embedding_facts,
        },
        commits,
        original,
        canonical: canonical_plan.facts,
    };
    plan.validate(source.reader())?;
    Ok(plan)
}

/// Publish a verified additive plan through the native collection facade.
/// Every legacy Memory writer must remain stopped from source freeze through
/// publication.  Exact replay is content-addressed and therefore idempotent.
pub fn publish(
    source: &FrozenSource,
    plan: &MemoryCollectionMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Memory migration plan does not belong to this frozen source");
    }
    plan.validate(source.reader())?;

    let signer = load_signer(target, key)?;
    let mut pile = open_pile_strict(target)?;
    let result = (|| {
        let existing = faculties::collection_names::open(&mut pile, schema::DEFAULT_SCOPE_ID, signer.clone())
            .materialize()
            .context("materialize prior native Memory collection")?;
        let reader = pile.reader().context("open Memory migration reader")?;
        memory::validate_catalog(&reader, &existing)
            .context("validate prior native Memory collection")?;

        let mut candidate = Fragment::empty();
        for commit in &plan.commits {
            candidate += commit.fragment.clone();
        }
        memory::validate_candidate(&reader, &existing, &candidate)
            .context("preflight native Memory plus additive legacy projection")?;

        let mut published = Vec::with_capacity(plan.commits.len());
        {
            let mut collection =
                faculties::collection_names::open(&mut pile, schema::DEFAULT_SCOPE_ID, signer.clone());
            for commit in &plan.commits {
                published.push(
                    collection
                        .commit(commit.fragment.clone())
                        .context("publish migrated Memory commit")?,
                );
            }
        }

        let actual = faculties::collection_names::open(&mut pile, schema::DEFAULT_SCOPE_ID, signer)
            .materialize()
            .context("materialize migrated Memory collection")?;
        let reader = pile.reader().context("open migrated Memory reader")?;
        memory::validate_catalog(&reader, &actual).context("validate migrated Memory")?;
        let mut expected = existing;
        expected += plan.materialized_facts();
        if actual != expected {
            bail!("Memory migration result differs from prior native union additive projection");
        }
        Ok(published)
    })();
    match (result, pile.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(anyhow!("close Memory migration pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Memory migration pile also failed: {close_error}"
        ))),
    }
}

fn commit_hex(commit: LegacyCommitId) -> String {
    hex::encode_upper(commit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use triblespace::core::collection::Collection;
    use triblespace::core::repo::{BlobStore, Repository};

    use crate::collection_cutover::{freeze_source};
use faculties::storage::{initialize_signer, load_signer, open_pile_strict};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-memory-cutover-{}-{serial}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn point(seconds: f64) -> memory::IntervalValue {
        let at = hifitime::Epoch::from_tai_seconds(seconds);
        (at, at).try_to_inline().unwrap()
    }

    fn commit(byte: u8) -> LegacyCommitId {
        [byte; 32]
    }

    fn serial_commit(serial: u32) -> LegacyCommitId {
        let mut commit = [0u8; 32];
        commit[28..].copy_from_slice(&serial.to_be_bytes());
        commit
    }

    fn legacy(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn facts(fragment: Fragment) -> TribleSet {
        fragment.facts().clone()
    }

    fn chunk(
        id: Id,
        summary: &str,
        observed: f64,
        supersedes: impl IntoIterator<Item = Id>,
    ) -> TribleSet {
        let summary = summary.to_owned().to_blob().get_handle();
        let supersedes: BTreeSet<_> = supersedes.into_iter().collect();
        facts(entity! { ExclusiveId::force_ref(&id) @
            metadata::tag: &KIND_CHUNK_ID,
            ctx::summary: summary,
            ctx::start_at: point(10.0),
            ctx::end_at: point(20.0),
            ctx::supersedes*: supersedes.iter(),
            metadata::created_at: point(observed),
        })
    }

    fn retraction(id: Id, target: Id, observed: f64) -> TribleSet {
        facts(entity! { ExclusiveId::force_ref(&id) @
            metadata::tag: &KIND_RETRACTION,
            ctx::supersedes: target,
            metadata::created_at: point(observed),
        })
    }

    fn delta(
        byte: u8,
        parents: impl IntoIterator<Item = u8>,
        facts: TribleSet,
        authored: bool,
    ) -> LegacyMemoryDelta {
        LegacyMemoryDelta {
            commit: commit(byte),
            parents: parents.into_iter().map(commit).collect(),
            facts,
            authored,
        }
    }

    fn assert_disjoint(plan: &MemoryMigrationPlan) {
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
            &ctx::reference.id(),
            &first,
        ));
        all.insert(&Trible::force(
            ExclusiveId::force_ref(&entity),
            &ctx::reference.id(),
            &second,
        ));
        all.insert(&Trible::force(
            ExclusiveId::force_ref(&entity),
            &ctx::supersedes.id(),
            &first,
        ));

        for serial in 0u32..4096 {
            let mut raw = [0x91; 16];
            raw[12..].copy_from_slice(&serial.to_be_bytes());
            let noise = Id::new(raw).unwrap();
            all.insert(&Trible::force(
                ExclusiveId::force_ref(&noise),
                &ctx::reference.id(),
                &first,
            ));
        }

        assert_eq!(
            values(&all, entity, &ctx::reference),
            BTreeSet::from([first, second])
        );
        assert!(values(&all, legacy(0x84), &ctx::reference).is_empty());
    }

    #[test]
    fn incremental_frontier_is_the_exact_order_independent_antichain_join() {
        let a = legacy(0xa1);
        let b = legacy(0xb1);
        let c = legacy(0xc1);
        let d = legacy(0xd1);
        let e = legacy(0xe1);
        let f = legacy(0xf1);
        let ids = [a, b, c, d, e, f];
        let graph = BTreeMap::from([
            (a, BTreeSet::new()),
            (b, BTreeSet::from([a])),
            (c, BTreeSet::from([a])),
            (d, BTreeSet::from([b])),
            (e, BTreeSet::from([b, c])),
            (f, BTreeSet::from([d, e])),
        ]);

        let reference_is_ancestor = |ancestor: Id, node: Id| {
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
        };

        for mask in 0u32..(1 << ids.len()) {
            let selected: BTreeSet<_> = ids
                .iter()
                .enumerate()
                .filter_map(|(bit, id)| ((mask & (1 << bit)) != 0).then_some(*id))
                .collect();
            let expected: BTreeSet<_> = selected
                .iter()
                .filter(|candidate| {
                    !selected.iter().any(|other| {
                        candidate != &other && reference_is_ancestor(**candidate, *other)
                    })
                })
                .copied()
                .collect();

            let mut ascending = BTreeSet::new();
            let mut cache = BTreeMap::new();
            merge_frontier(&mut ascending, selected.iter().copied(), &graph, &mut cache);
            assert_eq!(ascending, expected);

            let mut descending = BTreeSet::new();
            merge_frontier(
                &mut descending,
                selected.iter().rev().copied(),
                &graph,
                &mut BTreeMap::new(),
            );
            assert_eq!(descending, expected);

            let mut left = BTreeSet::new();
            let mut right = BTreeSet::new();
            let split = selected.len() / 2;
            merge_frontier(
                &mut left,
                selected.iter().take(split).copied(),
                &graph,
                &mut BTreeMap::new(),
            );
            merge_frontier(
                &mut right,
                selected.iter().skip(split).copied(),
                &graph,
                &mut BTreeMap::new(),
            );
            merge_frontier(&mut left, right, &graph, &mut BTreeMap::new());
            assert_eq!(left, expected);
        }
    }

    #[test]
    fn long_linear_history_moves_one_live_state_without_copying_it() {
        const COMMITS: u32 = 2048;
        let chunk_id = legacy(0x85);
        let mut deltas = Vec::with_capacity(COMMITS as usize);
        deltas.push(LegacyMemoryDelta {
            commit: serial_commit(1),
            parents: BTreeSet::new(),
            facts: chunk(chunk_id, "linear", 1.0, []),
            authored: true,
        });
        for serial in 2..=COMMITS {
            deltas.push(LegacyMemoryDelta {
                commit: serial_commit(serial),
                parents: BTreeSet::from([serial_commit(serial - 1)]),
                facts: TribleSet::new(),
                authored: true,
            });
        }

        let (plan, profile) = plan_legacy_memory_profiled(deltas).unwrap();
        assert_eq!(profile.fork_state_clones, 0);
        assert_eq!(profile.peak_retained_states, 1);
        assert_eq!(plan.facts_by_commit.len(), COMMITS as usize);
        assert_eq!(memory::load_catalog(&plan.facts).unwrap().chunks.len(), 1);
        assert!(plan.aliases.contains_key(&chunk_id));
        assert_disjoint(&plan);
    }

    #[test]
    fn additive_cutover_preserves_authored_units_and_is_exactly_replayable() {
        let directory = TestDirectory::new();
        let pile_path = directory.0.join("memory.pile");
        let key_path = directory.0.join("memory.key");
        File::create(&pile_path).unwrap();
        initialize_signer(&pile_path, Some(&key_path)).unwrap();

        let legacy_signer = SigningKey::from_bytes(&[0x91; 32]);
        let pile = open_pile_strict(&pile_path).unwrap();
        let mut repository = Repository::new(pile, legacy_signer, Fragment::empty()).unwrap();
        let branch = *repository
            .create_branch(schema::LEGACY_MEMORY_BRANCH_NAME, None)
            .unwrap();
        let mut workspace = repository.pull(branch).unwrap();
        let legacy_id = Id::new([0x92; 16]).unwrap();
        let mut legacy = Fragment::empty();
        let summary = legacy.put::<blobencodings::UTF8String, _>("legacy memory".to_owned());
        legacy += entity! { ExclusiveId::force_ref(&legacy_id) @
            metadata::tag: &KIND_CHUNK_ID,
            ctx::summary: summary,
            ctx::start_at: point(10.0),
            ctx::end_at: point(20.0),
            metadata::created_at: point(30.0),
        };
        let original = legacy.facts().clone();
        workspace.commit(legacy, "legacy Memory event");
        workspace.commit(Fragment::empty(), "authored empty Memory event");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();

        let source = freeze_source(&pile_path).unwrap();
        let plan = plan(&source).unwrap();
        assert_eq!(plan.report().authored_commits, 2);
        assert_eq!(plan.original_facts(), &original);
        assert_eq!(plan.report().canonical_nodes, 1);
        assert!(plan
            .commits()
            .iter()
            .any(|commit| commit.fragment.facts().is_empty()));
        plan.verify_conservation().unwrap();

        let frozen_branch = source
            .legacy_branch(schema::LEGACY_MEMORY_BRANCH_NAME)
            .unwrap()
            .unwrap();
        let projected = project_legacy_authored_commits(
            &source,
            &frozen_branch,
            validate_legacy_memory_payloads,
        )
        .unwrap();
        for expected in projected {
            let actual = plan
                .commits()
                .iter()
                .find(|commit| commit.source == expected.source)
                .unwrap();
            let mut expected_metadata = expected.metadata.facts().clone();
            expected_metadata += expected.metadata.metafacts().clone();
            assert_eq!(actual.fragment.metafacts(), &expected_metadata);
        }

        let published = publish(&source, &plan, &pile_path, Some(&key_path)).unwrap();
        assert_eq!(published.len(), 2);
        let signer = load_signer(&pile_path, Some(&key_path)).unwrap();
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let actual = {
            let mut collection = faculties::collection_names::open(&mut pile, schema::DEFAULT_SCOPE_ID, signer);
            collection.materialize().unwrap()
        };
        let reader = pile.reader().unwrap();
        let catalog = memory::validate_catalog(&reader, &actual).unwrap();
        assert_eq!(actual, plan.materialized_facts());
        assert_eq!(catalog.chunks.len(), 1);
        assert_eq!(catalog.alias_targets(legacy_id).len(), 1);
        assert!(actual
            .iter()
            .all(|fact| { original.contains(fact) || plan.canonical_facts().contains(fact) }));
        pile.close().unwrap();

        let length = fs::metadata(&pile_path).unwrap().len();
        let replay = publish(&source, &plan, &pile_path, Some(&key_path)).unwrap();
        assert_eq!(replay, published);
        assert_eq!(fs::metadata(&pile_path).unwrap().len(), length);
    }

    #[test]
    fn late_supersedes_amendment_becomes_join_without_moving_alias() {
        let old = legacy(0x11);
        let replacement = legacy(0x22);
        let amendment = facts(entity! {
            ExclusiveId::force_ref(&replacement) @ ctx::supersedes: old
        });
        let deltas = vec![
            delta(1, [], chunk(old, "old", 1.0, []), true),
            delta(2, [1], chunk(replacement, "replacement", 2.0, []), true),
            delta(3, [2], amendment, true),
            delta(4, [3], TribleSet::new(), true),
        ];

        let plan = plan_legacy_memory(deltas.clone()).unwrap();
        let catalog = memory::load_catalog(&plan.facts).unwrap();
        let old_canonical = plan.aliases[&old];
        let replacement_base = plan.aliases[&replacement];
        assert_eq!(catalog.alias_targets(replacement), vec![replacement_base]);
        assert_eq!(catalog.chunks.len(), 3);
        let successor = *catalog
            .chunks
            .keys()
            .find(|id| **id != old_canonical && **id != replacement_base)
            .unwrap();
        assert_eq!(
            catalog.chunks[&successor].predecessors,
            BTreeSet::from([old_canonical, replacement_base])
        );
        assert_eq!(catalog.head_ids(), vec![successor]);
        assert!(plan.facts_by_commit[&commit(4)].is_empty());
        assert_disjoint(&plan);

        let mut reversed = deltas;
        reversed.reverse();
        assert_eq!(plan, plan_legacy_memory(reversed).unwrap());
    }

    #[test]
    fn repository_fork_keeps_correction_and_retraction_visible() {
        let base = legacy(0x31);
        let corrected = legacy(0x32);
        let withdrawn = legacy(0x33);
        let deltas = vec![
            delta(1, [], chunk(base, "base", 1.0, []), true),
            delta(2, [1], chunk(corrected, "corrected", 50.0, [base]), true),
            // An older clock cannot make this branch disappear.
            delta(3, [1], retraction(withdrawn, base, 2.0), true),
            delta(4, [2, 3], TribleSet::new(), false),
            delta(5, [4], TribleSet::new(), true),
        ];
        let (plan, profile) = plan_legacy_memory_profiled(deltas.clone()).unwrap();
        assert_eq!(profile.fork_state_clones, 1);
        assert_eq!(profile.peak_retained_states, 2);
        let catalog = memory::load_catalog(&plan.facts).unwrap();
        assert_eq!(catalog.head_ids().len(), 2);
        assert_eq!(catalog.live_chunk_ids(), vec![plan.aliases[&corrected]]);
        assert_eq!(catalog.retractions.len(), 1);
        assert!(!plan.facts_by_commit.contains_key(&commit(4)));
        assert!(plan.facts_by_commit[&commit(5)].is_empty());
        assert_disjoint(&plan);

        let mut reversed = deltas;
        reversed.reverse();
        let (reordered, reordered_profile) = plan_legacy_memory_profiled(reversed).unwrap();
        assert_eq!(reordered, plan);
        assert_eq!(reordered_profile, profile);
    }

    #[test]
    fn repository_merge_preserves_incomparable_states_of_one_legacy_entity() {
        let retired_a = legacy(0x71);
        let retired_b = legacy(0x72);
        let amended = legacy(0x73);
        let mut root = chunk(retired_a, "retired a", 1.0, []);
        root += chunk(retired_b, "retired b", 1.0, []);
        root += chunk(amended, "amended", 1.0, []);
        let left = facts(entity! {
            ExclusiveId::force_ref(&amended) @ ctx::supersedes: retired_a
        });
        let right = facts(entity! {
            ExclusiveId::force_ref(&amended) @ ctx::supersedes: retired_b
        });
        let deltas = vec![
            delta(1, [], root, true),
            delta(2, [1], left, true),
            delta(3, [1], right, true),
            delta(4, [2, 3], TribleSet::new(), false),
        ];

        let plan = plan_legacy_memory(deltas.clone()).unwrap();
        let catalog = memory::load_catalog(&plan.facts).unwrap();
        assert_eq!(catalog.head_ids().len(), 2);
        assert!(catalog
            .head_ids()
            .iter()
            .all(|head| catalog.chunks.contains_key(head)));
        assert_eq!(catalog.chunks.len(), 5);
        assert_eq!(catalog.alias_targets(amended), vec![plan.aliases[&amended]]);
        assert_disjoint(&plan);

        let mut reversed = deltas;
        reversed.reverse();
        assert_eq!(plan_legacy_memory(reversed).unwrap(), plan);
    }

    #[test]
    fn repository_merge_discards_an_ancestor_state_before_observation() {
        let retired = legacy(0x74);
        let amended = legacy(0x75);
        let mut root = chunk(retired, "retired", 1.0, []);
        root += chunk(amended, "amended", 1.0, []);
        let amendment = facts(entity! {
            ExclusiveId::force_ref(&amended) @ ctx::supersedes: retired
        });
        let observation = facts(entity! {
            ExclusiveId::force_ref(&amended) @ metadata::created_at: point(5.0)
        });
        let plan = plan_legacy_memory([
            delta(1, [], root, true),
            delta(2, [1], amendment, true),
            delta(3, [1], TribleSet::new(), true),
            delta(4, [2, 3], TribleSet::new(), false),
            delta(5, [4], observation, true),
        ])
        .unwrap();

        let catalog = memory::load_catalog(&plan.facts).unwrap();
        assert_eq!(catalog.head_ids().len(), 1);
        assert_ne!(catalog.head_ids()[0], plan.aliases[&amended]);
        assert!(plan.facts_by_commit[&commit(5)]
            .iter()
            .any(|fact| fact.a() == &metadata::created_at.id()));
        assert_disjoint(&plan);
    }

    #[test]
    fn historical_untyped_redaction_marker_becomes_a_canonical_retraction() {
        let retired_a = legacy(0x34);
        let retired_b = legacy(0x35);
        let base = legacy(0x36);
        let marker = legacy(0x37);
        let first_amendment = facts(entity! {
            ExclusiveId::force_ref(&base) @ ctx::supersedes: retired_a
        });
        let second_amendment = facts(entity! {
            ExclusiveId::force_ref(&base) @ ctx::supersedes: retired_b
        });
        let redaction = facts(entity! {
            ExclusiveId::force_ref(&marker) @ ctx::supersedes: base
        });
        let plan = plan_legacy_memory([
            delta(1, [], chunk(retired_a, "retired a", 1.0, []), true),
            delta(2, [1], chunk(retired_b, "retired b", 2.0, []), true),
            delta(3, [2], chunk(base, "base", 3.0, []), true),
            delta(4, [3], first_amendment, true),
            delta(5, [4], second_amendment, true),
            delta(6, [5], redaction, true),
        ])
        .unwrap();
        let catalog = memory::load_catalog(&plan.facts).unwrap();
        assert_eq!(catalog.retractions.len(), 1);
        let retraction = catalog.retractions.values().next().unwrap();
        assert_eq!(retraction.predecessors.len(), 1);
        let amended_head = *retraction.predecessors.first().unwrap();
        assert!(catalog.chunks.contains_key(&amended_head));
        assert_ne!(amended_head, plan.aliases[&base]);
        assert!(!plan.aliases.contains_key(&marker));
        assert_eq!(catalog.head_ids(), vec![retraction.id]);
        assert!(catalog.live_chunk_ids().is_empty());
        assert!(!plan
            .facts
            .iter()
            .any(|fact| fact.a() == &ctx::supersedes.id()));
        assert_disjoint(&plan);
    }

    #[test]
    fn untyped_redaction_marker_does_not_admit_chunk_fields() {
        let base = legacy(0x38);
        let marker = legacy(0x39);
        let malformed = facts(entity! { ExclusiveId::force_ref(&marker) @
            ctx::supersedes: base,
            ctx::start_at: point(2.0),
        });
        let error = plan_legacy_memory([
            delta(1, [], chunk(base, "base", 1.0, []), true),
            delta(2, [1], malformed, true),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("contains unsupported fact"));
    }

    #[test]
    fn cross_scope_references_are_reported_without_fabricated_identity() {
        let chunk_id = legacy(0x41);
        let exec = legacy(0x42);
        let archive = legacy(0x43);
        let summary = "foreign links".to_owned().to_blob().get_handle();
        let row = facts(entity! { ExclusiveId::force_ref(&chunk_id) @
            metadata::tag: &KIND_CHUNK_ID,
            ctx::summary: summary,
            ctx::start_at: point(1.0),
            ctx::end_at: point(2.0),
            ctx::about_exec_result: exec,
            ctx::about_archive_message: archive,
            metadata::created_at: point(3.0),
        });
        let plan = plan_legacy_memory([delta(1, [], row, true)]).unwrap();
        assert_eq!(
            plan.cross_scope_references,
            BTreeSet::from([
                CrossScopeReference {
                    legacy_chunk: chunk_id,
                    kind: CrossScopeReferenceKind::CognitionExecResult,
                    legacy_target: exec,
                },
                CrossScopeReference {
                    legacy_chunk: chunk_id,
                    kind: CrossScopeReferenceKind::ArchiveMessage,
                    legacy_target: archive,
                },
            ])
        );
        let canonical = plan.aliases[&chunk_id];
        let catalog = memory::load_catalog(&plan.facts).unwrap();
        assert_eq!(catalog.chunks[&canonical].about_exec_result, Some(exec));
        assert_eq!(
            catalog.chunks[&canonical].about_archive_message,
            Some(archive)
        );
    }

    #[test]
    fn same_delta_references_resolve_by_dependency_not_random_id_order() {
        let referencing = legacy(0x51);
        let referenced = legacy(0x61);
        let mut rows = chunk(referencing, "referring", 1.0, []);
        rows += facts(entity! {
            ExclusiveId::force_ref(&referencing) @ ctx::reference: referenced
        });
        rows += chunk(referenced, "referenced", 1.0, []);
        let plan = plan_legacy_memory([delta(1, [], rows, true)]).unwrap();
        let catalog = memory::load_catalog(&plan.facts).unwrap();
        assert_eq!(
            catalog.chunks[&plan.aliases[&referencing]].references,
            BTreeSet::from([plan.aliases[&referenced]])
        );
    }
}
