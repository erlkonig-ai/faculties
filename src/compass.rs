//! Collection-native Compass values, validation, and fork-visible reads.
//!
//! The authored collection is a union of four deliberately different
//! algebras:
//!
//! - a stable goal anchor with one immutable intrinsic genesis;
//! - independent additive note occurrences;
//! - an intrinsic per-goal status snapshot DAG; and
//! - one intrinsic full-board priority snapshot DAG.
//!
//! No read uses a timestamp or iteration order to choose a winner. Replica
//! union may expose a fork; reconciliation is another child naming every live
//! predecessor. Status timestamps and attribution remain event provenance and
//! therefore participate in snapshot identity. Concurrent heads with the same
//! scalar value are preserved but resolve as [`StatusResolution::Agreed`]
//! rather than as a divergent fork. Board-priority heads are quotiented the
//! same way by equality of their complete edge sets.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::macros::{entity, find, pattern};
use triblespace::prelude::*;

use crate::schemas::compass::{
    event, goal, note, priority, status, KIND_GOAL, KIND_GOAL_GENESIS, KIND_NOTE,
    KIND_PRIORITY_EDGE, KIND_PRIORITY_SNAPSHOT, KIND_STATUS_SNAPSHOT, KIND_TAG,
};

pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalGenesis {
    pub id: Id,
    pub goal: Id,
    pub title: TextHandle,
    pub tags: Vec<Id>,
    pub parent: Option<Id>,
    pub created_at: IntervalValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteRecord {
    pub id: Id,
    pub occurrence: Id,
    pub goal: Id,
    pub body: TextHandle,
    pub tags: Vec<Id>,
    pub references: Vec<TextHandle>,
    pub supersedes: Vec<Id>,
    pub by: Option<Id>,
    pub created_at: IntervalValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusSnapshot {
    pub id: Id,
    pub goal: Id,
    pub value: String,
    pub predecessors: Vec<Id>,
    pub by: Option<Id>,
    pub created_at: IntervalValue,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PriorityEdge {
    pub id: Id,
    pub higher: Id,
    pub lower: Id,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrioritySnapshot {
    pub id: Id,
    pub edges: BTreeSet<(Id, Id)>,
    pub predecessors: Vec<Id>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TagRecord {
    pub id: Id,
    pub name: TextHandle,
}

/// Fork-visible state of one goal's status track.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatusResolution {
    Missing,
    Unique(StatusSnapshot),
    /// Multiple live transition records carry the same scalar value. Their
    /// event provenance remains distinct, but the status is semantically
    /// settled; the next transition still names every head.
    Agreed(Vec<StatusSnapshot>),
    Forked(Vec<StatusSnapshot>),
    Invalid(String),
}

/// Fork-visible state of the one board-wide priority track.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PriorityResolution {
    Missing,
    Unique(PrioritySnapshot),
    /// Multiple live histories carry the same complete edge set. The board is
    /// semantically settled, while every head remains a join obligation.
    Agreed(Vec<PrioritySnapshot>),
    Forked(Vec<PrioritySnapshot>),
    Invalid(String),
}

impl StatusResolution {
    pub fn head_ids(&self) -> Vec<Id> {
        match self {
            Self::Missing | Self::Invalid(_) => Vec::new(),
            Self::Unique(snapshot) => vec![snapshot.id],
            Self::Agreed(snapshots) | Self::Forked(snapshots) => {
                snapshots.iter().map(|snapshot| snapshot.id).collect()
            }
        }
    }
}

impl PriorityResolution {
    pub fn head_ids(&self) -> Vec<Id> {
        match self {
            Self::Missing | Self::Invalid(_) => Vec::new(),
            Self::Unique(snapshot) => vec![snapshot.id],
            Self::Agreed(snapshots) | Self::Forked(snapshots) => {
                snapshots.iter().map(|snapshot| snapshot.id).collect()
            }
        }
    }
}

fn sorted_ids(values: impl IntoIterator<Item = Id>) -> Vec<Id> {
    let mut values: Vec<Id> = values.into_iter().collect();
    values.sort_unstable();
    values.dedup();
    values
}

fn sorted_handles(values: impl IntoIterator<Item = TextHandle>) -> Vec<TextHandle> {
    let mut values: Vec<TextHandle> = values.into_iter().collect();
    values.sort_unstable_by_key(|value| value.raw);
    values.dedup();
    values
}

fn canonical_required(value: impl Into<String>, field: &str) -> Result<String> {
    let value = value.into();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{field} is empty");
    }
    if trimmed.bytes().any(|byte| byte == 0) {
        bail!("{field} contains a NUL byte");
    }
    Ok(trimmed.to_owned())
}

pub fn canonical_tag(value: impl Into<String>) -> Result<String> {
    let value = value.into();
    let value = value.trim();
    let value = value.strip_prefix('#').unwrap_or(value).trim();
    // ASCII folding is deliberately version-independent. Non-ASCII labels
    // retain their exact spelling instead of depending on a Unicode table.
    let value = canonical_required(value, "tag")?.to_ascii_lowercase();
    Ok(value)
}

fn canonical_tag_set(values: Vec<String>) -> Result<Vec<String>> {
    let mut values: Vec<String> = values
        .into_iter()
        .map(canonical_tag)
        .collect::<Result<_>>()?;
    values.sort();
    values.dedup();
    Ok(values)
}

pub fn canonical_status(value: impl Into<String>) -> Result<String> {
    let value = canonical_required(value, "status")?.to_ascii_lowercase();
    if value.len() > 32 {
        bail!("status exceeds 32 UTF-8 bytes: {value}");
    }
    Ok(value)
}

fn point_interval(value: IntervalValue, field: &str) -> Result<()> {
    let (lower, upper): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode {field}: {error:?}"))?;
    if lower != upper {
        bail!("{field} must be a point interval");
    }
    Ok(())
}

fn goal_anchor_record(goal_id: Id) -> Fragment {
    entity! { ExclusiveId::force_ref(&goal_id) @ metadata::tag: &KIND_GOAL }
}

fn goal_genesis_record(
    goal_id: Id,
    title: TextHandle,
    user_tags: &[Id],
    parent: Option<Id>,
    created_at: IntervalValue,
) -> Fragment {
    let tags: Vec<Id> = std::iter::once(KIND_GOAL_GENESIS)
        .chain(user_tags.iter().copied())
        .collect();
    entity! {
        metadata::tag*: tags.iter(),
        goal::of: &goal_id,
        goal::title: title,
        goal::parent?: parent,
        metadata::created_at: created_at,
    }
}

#[allow(clippy::too_many_arguments)]
fn note_record_fragment(
    occurrence: Id,
    goal_id: Id,
    body: TextHandle,
    user_tags: &[Id],
    references: &[TextHandle],
    supersedes: &[Id],
    by: Option<Id>,
    created_at: IntervalValue,
) -> Fragment {
    let tags: Vec<Id> = std::iter::once(KIND_NOTE)
        .chain(user_tags.iter().copied())
        .collect();
    entity! {
        metadata::tag*: tags.iter(),
        note::occurrence: &occurrence,
        note::of: &goal_id,
        note::body: body,
        note::reference*: references.iter(),
        metadata::supersedes*: supersedes.iter(),
        event::by?: by,
        metadata::created_at: created_at,
    }
}

fn tag_record_fragment(name: TextHandle) -> Fragment {
    entity! {
        metadata::tag: &KIND_TAG,
        metadata::name: name,
    }
}

fn put_tags(fragment: &mut Fragment, labels: Vec<String>) -> Result<Vec<Id>> {
    let labels = canonical_tag_set(labels)?;
    let mut ids = Vec::with_capacity(labels.len());
    for label in labels {
        let name = fragment.put(label);
        let tag = tag_record_fragment(name);
        ids.push(tag.root().expect("tag has one intrinsic root"));
        *fragment += tag;
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

/// Build one canonical intrinsic tag entity. Case, surrounding whitespace,
/// and one optional display `#` do not affect its identity.
pub fn tag_fragment(label: impl Into<String>) -> Result<(Fragment, Id, String)> {
    let label = canonical_tag(label)?;
    let mut fragment = Fragment::empty();
    let ids = put_tags(&mut fragment, vec![label.clone()])?;
    Ok((fragment, ids[0], label))
}

fn status_record(
    goal_id: Id,
    value: &str,
    predecessors: &[Id],
    by: Option<Id>,
    created_at: IntervalValue,
) -> Fragment {
    entity! {
        metadata::tag: &KIND_STATUS_SNAPSHOT,
        status::of: &goal_id,
        status::value: value,
        metadata::supersedes*: predecessors.iter(),
        event::by?: by,
        metadata::created_at: created_at,
    }
}

fn priority_edge_record(higher: Id, lower: Id) -> Fragment {
    entity! {
        metadata::tag: &KIND_PRIORITY_EDGE,
        priority::higher: &higher,
        priority::lower: &lower,
    }
}

fn priority_snapshot_record(edge_ids: &[Id], predecessors: &[Id]) -> Fragment {
    entity! {
        metadata::tag: &KIND_PRIORITY_SNAPSHOT,
        priority::edge*: edge_ids.iter(),
        metadata::supersedes*: predecessors.iter(),
    }
}

/// Build one goal anchor, immutable genesis, and initial status snapshot.
pub fn goal_fragment(
    goal_id: Id,
    title: impl Into<String>,
    tags: Vec<String>,
    parent: Option<Id>,
    initial_status: impl Into<String>,
    by: Option<Id>,
    created_at: IntervalValue,
) -> Result<(Fragment, Id, Id)> {
    point_interval(created_at, "goal creation time")?;
    let title = canonical_required(title, "goal title")?;
    let status = canonical_status(initial_status)?;

    let mut fragment = Fragment::empty();
    let title = fragment.put(title);
    let tags = put_tags(&mut fragment, tags)?;
    let genesis_fragment = goal_genesis_record(goal_id, title, &tags, parent, created_at);
    let genesis_id = genesis_fragment
        .root()
        .expect("goal genesis has one intrinsic root");
    fragment += goal_anchor_record(goal_id);
    fragment += genesis_fragment;

    let status_fragment = status_fragment(goal_id, status, &[], by, created_at)?;
    let status_id = status_fragment
        .root()
        .expect("status snapshot has one intrinsic root");
    fragment += status_fragment;
    Ok((fragment, genesis_id, status_id))
}

/// Build one independent note occurrence. Identical notes remain distinct when
/// callers supply distinct occurrence tokens.
pub fn note_fragment(
    occurrence: Id,
    goal_id: Id,
    body: impl Into<String>,
    tags: Vec<String>,
    references: Vec<String>,
    supersedes: &[Id],
    by: Option<Id>,
    created_at: IntervalValue,
) -> Result<(Fragment, Id)> {
    point_interval(created_at, "note creation time")?;
    let body = body.into();
    if body.bytes().any(|byte| byte == 0) {
        bail!("note body contains a NUL byte");
    }
    let mut references: Vec<String> = references
        .into_iter()
        .map(|reference| canonical_required(reference, "note reference"))
        .collect::<Result<_>>()?;
    references.sort();
    references.dedup();

    let mut fragment = Fragment::empty();
    let body = fragment.put(body);
    let tags = put_tags(&mut fragment, tags)?;
    let references: Vec<TextHandle> = references
        .into_iter()
        .map(|reference| fragment.put(reference))
        .collect();
    let supersedes = sorted_ids(supersedes.iter().copied());
    let note = note_record_fragment(
        occurrence,
        goal_id,
        body,
        &tags,
        &references,
        &supersedes,
        by,
        created_at,
    );
    let note_id = note.root().expect("note has one intrinsic root");
    fragment += note;
    Ok((fragment, note_id))
}

/// Build an intrinsic complete scalar status successor.
pub fn status_fragment(
    goal_id: Id,
    value: impl Into<String>,
    predecessors: &[Id],
    by: Option<Id>,
    created_at: IntervalValue,
) -> Result<Fragment> {
    point_interval(created_at, "status creation time")?;
    let value = canonical_status(value)?;
    let predecessors = sorted_ids(predecessors.iter().copied());
    Ok(status_record(
        goal_id,
        &value,
        &predecessors,
        by,
        created_at,
    ))
}

/// Build an intrinsic complete board-priority snapshot and all referenced
/// intrinsic edge records.
pub fn priority_snapshot_fragment(
    edges: impl IntoIterator<Item = (Id, Id)>,
    predecessors: &[Id],
) -> Result<(Fragment, Id)> {
    let edges: BTreeSet<(Id, Id)> = edges.into_iter().collect();
    if let Some((id, _)) = edges.iter().find(|(higher, lower)| higher == lower) {
        bail!("goal {id:x} cannot be prioritized over itself");
    }

    let mut fragment = Fragment::empty();
    let mut edge_ids = Vec::with_capacity(edges.len());
    for &(higher, lower) in &edges {
        let edge_fragment = priority_edge_record(higher, lower);
        edge_ids.push(
            edge_fragment
                .root()
                .expect("priority edge has one intrinsic root"),
        );
        fragment += edge_fragment;
    }
    edge_ids.sort_unstable();
    let predecessors = sorted_ids(predecessors.iter().copied());
    let snapshot = priority_snapshot_record(&edge_ids, &predecessors);
    let snapshot_id = snapshot
        .root()
        .expect("priority snapshot has one intrinsic root");
    fragment += snapshot;
    Ok((fragment, snapshot_id))
}

fn exactly_one<T>(values: Vec<T>, entity: Id, field: &str) -> Result<T> {
    let count = values.len();
    if count != 1 {
        bail!("Compass entity {entity:x} has {count} values for {field}; expected exactly one");
    }
    Ok(values.into_iter().next().unwrap())
}

fn at_most_one<T>(values: Vec<T>, entity: Id, field: &str) -> Result<Option<T>> {
    let count = values.len();
    if count > 1 {
        bail!("Compass entity {entity:x} has {count} values for {field}; expected at most one");
    }
    Ok(values.into_iter().next())
}

pub fn goal_anchors(facts: &TribleSet) -> BTreeSet<Id> {
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: &KIND_GOAL }])).collect()
}

fn ids_of_kind(facts: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: kind }])).collect()
}

fn attached_tags(facts: &TribleSet, entity: Id, kind: Id) -> Vec<Id> {
    sorted_ids(
        find!(value: Id, pattern!(facts, [{ entity @ metadata::tag: ?value }]))
            .filter(|value| *value != kind),
    )
}

pub fn tag_record(facts: &TribleSet, id: Id) -> Result<TagRecord> {
    Ok(TagRecord {
        id,
        name: exactly_one(
            find!(value: TextHandle, pattern!(facts, [{ id @ metadata::name: ?value }])).collect(),
            id,
            "metadata::name",
        )?,
    })
}

pub fn tag_ids(facts: &TribleSet) -> BTreeSet<Id> {
    ids_of_kind(facts, KIND_TAG)
}

pub fn goal_genesis(facts: &TribleSet, id: Id) -> Result<GoalGenesis> {
    Ok(GoalGenesis {
        id,
        goal: exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ goal::of: ?value }])).collect(),
            id,
            "goal::of",
        )?,
        title: exactly_one(
            find!(value: TextHandle, pattern!(facts, [{ id @ goal::title: ?value }])).collect(),
            id,
            "goal::title",
        )?,
        tags: attached_tags(facts, id, KIND_GOAL_GENESIS),
        parent: at_most_one(
            find!(value: Id, pattern!(facts, [{ id @ goal::parent: ?value }])).collect(),
            id,
            "goal::parent",
        )?,
        created_at: exactly_one(
            find!(value: IntervalValue, pattern!(facts, [{ id @ metadata::created_at: ?value }]))
                .collect(),
            id,
            "metadata::created_at",
        )?,
    })
}

pub fn genesis_for_goal(facts: &TribleSet, goal_id: Id) -> Result<Option<GoalGenesis>> {
    let ids: Vec<Id> = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_GOAL_GENESIS, goal::of: &goal_id }])
    )
    .collect();
    match ids.as_slice() {
        [] => Ok(None),
        [id] => Ok(Some(goal_genesis(facts, *id)?)),
        _ => bail!("goal {goal_id:x} has {} genesis records", ids.len()),
    }
}

pub fn note_record(facts: &TribleSet, id: Id) -> Result<NoteRecord> {
    Ok(NoteRecord {
        id,
        occurrence: exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ note::occurrence: ?value }])).collect(),
            id,
            "note::occurrence",
        )?,
        goal: exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ note::of: ?value }])).collect(),
            id,
            "note::of",
        )?,
        body: exactly_one(
            find!(value: TextHandle, pattern!(facts, [{ id @ note::body: ?value }])).collect(),
            id,
            "note::body",
        )?,
        tags: attached_tags(facts, id, KIND_NOTE),
        references: sorted_handles(find!(
            value: TextHandle,
            pattern!(facts, [{ id @ note::reference: ?value }])
        )),
        supersedes: sorted_ids(find!(
            value: Id,
            pattern!(facts, [{ id @ metadata::supersedes: ?value }])
        )),
        by: at_most_one(
            find!(value: Id, pattern!(facts, [{ id @ event::by: ?value }])).collect(),
            id,
            "event::by",
        )?,
        created_at: exactly_one(
            find!(value: IntervalValue, pattern!(facts, [{ id @ metadata::created_at: ?value }]))
                .collect(),
            id,
            "metadata::created_at",
        )?,
    })
}

pub fn notes_for_goal(facts: &TribleSet, goal_id: Id) -> Result<Vec<NoteRecord>> {
    let mut ids: Vec<Id> = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_NOTE, note::of: &goal_id }])
    )
    .collect();
    ids.sort_unstable();
    ids.dedup();
    ids.into_iter().map(|id| note_record(facts, id)).collect()
}

pub fn status_snapshot(facts: &TribleSet, id: Id) -> Result<StatusSnapshot> {
    Ok(StatusSnapshot {
        id,
        goal: exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ status::of: ?value }])).collect(),
            id,
            "status::of",
        )?,
        value: exactly_one(
            find!(value: String, pattern!(facts, [{ id @ status::value: ?value }])).collect(),
            id,
            "status::value",
        )?,
        predecessors: sorted_ids(find!(
            value: Id,
            pattern!(facts, [{ id @ metadata::supersedes: ?value }])
        )),
        by: at_most_one(
            find!(value: Id, pattern!(facts, [{ id @ event::by: ?value }])).collect(),
            id,
            "event::by",
        )?,
        created_at: exactly_one(
            find!(value: IntervalValue, pattern!(facts, [{ id @ metadata::created_at: ?value }]))
                .collect(),
            id,
            "metadata::created_at",
        )?,
    })
}

pub fn priority_edge(facts: &TribleSet, id: Id) -> Result<PriorityEdge> {
    Ok(PriorityEdge {
        id,
        higher: exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ priority::higher: ?value }])).collect(),
            id,
            "priority::higher",
        )?,
        lower: exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ priority::lower: ?value }])).collect(),
            id,
            "priority::lower",
        )?,
    })
}

pub fn priority_snapshot(facts: &TribleSet, id: Id) -> Result<PrioritySnapshot> {
    let edge_ids = sorted_ids(find!(
        value: Id,
        pattern!(facts, [{ id @ priority::edge: ?value }])
    ));
    let mut edges = BTreeSet::new();
    for edge_id in edge_ids {
        let edge = priority_edge(facts, edge_id)?;
        edges.insert((edge.higher, edge.lower));
    }
    Ok(PrioritySnapshot {
        id,
        edges,
        predecessors: sorted_ids(find!(
            value: Id,
            pattern!(facts, [{ id @ metadata::supersedes: ?value }])
        )),
    })
}

fn ensure_intrinsic(id: Id, record: Fragment, label: &str) -> Result<TribleSet> {
    let expected = record
        .root()
        .ok_or_else(|| anyhow!("{label} record has no unique intrinsic root"))?;
    if id != expected {
        bail!("{label} {id:x} does not match intrinsic root {expected:x}");
    }
    Ok(record.into_facts())
}

fn dag_heads(nodes: &BTreeMap<Id, Vec<Id>>, label: &str) -> Result<Vec<Id>> {
    if nodes.is_empty() {
        return Ok(Vec::new());
    }
    for (&node, predecessors) in nodes {
        for predecessor in predecessors {
            if !nodes.contains_key(predecessor) {
                bail!("{label} {node:x} cites missing or wrong-track predecessor {predecessor:x}");
            }
        }
    }

    fn visit(
        node: Id,
        nodes: &BTreeMap<Id, Vec<Id>>,
        visiting: &mut BTreeSet<Id>,
        visited: &mut BTreeSet<Id>,
        label: &str,
    ) -> Result<()> {
        if visited.contains(&node) {
            return Ok(());
        }
        if !visiting.insert(node) {
            bail!("{label} predecessor graph contains a cycle at {node:x}");
        }
        for predecessor in &nodes[&node] {
            visit(*predecessor, nodes, visiting, visited, label)?;
        }
        visiting.remove(&node);
        visited.insert(node);
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for &node in nodes.keys() {
        visit(node, nodes, &mut visiting, &mut visited, label)?;
    }

    let superseded: BTreeSet<Id> = nodes
        .values()
        .flat_map(|predecessors| predecessors.iter().copied())
        .collect();
    Ok(nodes
        .keys()
        .filter(|id| !superseded.contains(*id))
        .copied()
        .collect())
}

fn status_resolution_result(facts: &TribleSet, goal_id: Id) -> Result<StatusResolution> {
    let ids: BTreeSet<Id> = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_STATUS_SNAPSHOT, status::of: &goal_id }])
    )
    .collect();
    if ids.is_empty() {
        return Ok(StatusResolution::Missing);
    }
    let mut snapshots = BTreeMap::new();
    let mut graph = BTreeMap::new();
    for id in ids {
        let snapshot = status_snapshot(facts, id)?;
        ensure_status_intrinsic(&snapshot)?;
        graph.insert(id, snapshot.predecessors.clone());
        snapshots.insert(id, snapshot);
    }
    let heads = dag_heads(&graph, "status snapshot")?;
    match heads.as_slice() {
        [] => bail!("status track for goal {goal_id:x} has no head"),
        [id] => Ok(StatusResolution::Unique(snapshots.remove(id).unwrap())),
        _ => {
            let heads: Vec<_> = heads
                .into_iter()
                .map(|id| snapshots.remove(&id).unwrap())
                .collect();
            let first = &heads[0].value;
            if heads.iter().all(|snapshot| snapshot.value == *first) {
                Ok(StatusResolution::Agreed(heads))
            } else {
                Ok(StatusResolution::Forked(heads))
            }
        }
    }
}

pub fn status_resolution(facts: &TribleSet, goal_id: Id) -> StatusResolution {
    status_resolution_result(facts, goal_id)
        .unwrap_or_else(|error| StatusResolution::Invalid(format!("{error:#}")))
}

fn priority_resolution_result(facts: &TribleSet) -> Result<PriorityResolution> {
    let ids = ids_of_kind(facts, KIND_PRIORITY_SNAPSHOT);
    if ids.is_empty() {
        return Ok(PriorityResolution::Missing);
    }
    let mut snapshots = BTreeMap::new();
    let mut graph = BTreeMap::new();
    for id in ids {
        let snapshot = validate_priority_snapshot_intrinsic(facts, id)?;
        graph.insert(id, snapshot.predecessors.clone());
        snapshots.insert(id, snapshot);
    }
    let heads = dag_heads(&graph, "priority snapshot")?;
    match heads.as_slice() {
        [] => bail!("priority snapshot track has no head"),
        [id] => Ok(PriorityResolution::Unique(snapshots.remove(id).unwrap())),
        _ => {
            let heads: Vec<_> = heads
                .into_iter()
                .map(|id| snapshots.remove(&id).unwrap())
                .collect();
            let first = &heads[0].edges;
            if heads.iter().all(|snapshot| snapshot.edges == *first) {
                Ok(PriorityResolution::Agreed(heads))
            } else {
                Ok(PriorityResolution::Forked(heads))
            }
        }
    }
}

pub fn priority_resolution(facts: &TribleSet) -> PriorityResolution {
    priority_resolution_result(facts)
        .unwrap_or_else(|error| PriorityResolution::Invalid(format!("{error:#}")))
}

pub fn explicit_priority_edges(facts: &TribleSet) -> Result<BTreeSet<(Id, Id)>> {
    match priority_resolution(facts) {
        PriorityResolution::Missing => Ok(BTreeSet::new()),
        PriorityResolution::Unique(snapshot) => Ok(snapshot.edges),
        PriorityResolution::Agreed(snapshots) => Ok(snapshots
            .into_iter()
            .next()
            .expect("agreed priority has at least two heads")
            .edges),
        PriorityResolution::Forked(snapshots) => bail!(
            "priority state is forked at heads {}; use `compass priority-resolve` with the complete intended edge set",
            snapshots
                .iter()
                .map(|snapshot| format!("{:x}", snapshot.id))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        PriorityResolution::Invalid(reason) => bail!("priority state is invalid: {reason}"),
    }
}

pub fn parent_edges(facts: &TribleSet) -> Result<BTreeSet<(Id, Id)>> {
    let mut edges = BTreeSet::new();
    for goal_id in goal_anchors(facts) {
        if let Some(parent) = genesis_for_goal(facts, goal_id)?.and_then(|value| value.parent) {
            edges.insert((goal_id, parent));
        }
    }
    Ok(edges)
}

pub fn effective_priority_edges(
    facts: &TribleSet,
    explicit: &BTreeSet<(Id, Id)>,
) -> Result<BTreeSet<(Id, Id)>> {
    let mut edges = explicit.clone();
    edges.extend(parent_edges(facts)?);
    Ok(edges)
}

pub fn validate_acyclic_edges(
    goals: &BTreeSet<Id>,
    edges: &BTreeSet<(Id, Id)>,
    label: &str,
) -> Result<()> {
    let mut outgoing: BTreeMap<Id, Vec<Id>> = BTreeMap::new();
    let mut indegree: BTreeMap<Id, usize> = goals.iter().map(|id| (*id, 0)).collect();
    for &(higher, lower) in edges {
        if higher == lower {
            bail!("{label} contains self edge {higher:x}");
        }
        if !goals.contains(&higher) || !goals.contains(&lower) {
            bail!("{label} edge {higher:x}>{lower:x} names an undeclared goal");
        }
        outgoing.entry(higher).or_default().push(lower);
        *indegree.entry(lower).or_default() += 1;
    }
    let mut ready: BTreeSet<Id> = indegree
        .iter()
        .filter_map(|(&id, &degree)| (degree == 0).then_some(id))
        .collect();
    let mut visited = 0;
    while let Some(node) = ready.pop_first() {
        visited += 1;
        for lower in outgoing.get(&node).into_iter().flatten() {
            let degree = indegree.get_mut(lower).unwrap();
            *degree -= 1;
            if *degree == 0 {
                ready.insert(*lower);
            }
        }
    }
    if visited != goals.len() {
        bail!("{label} contains a cycle");
    }
    Ok(())
}

pub fn validate_priority_edges(facts: &TribleSet, explicit: &BTreeSet<(Id, Id)>) -> Result<()> {
    let goals = goal_anchors(facts);
    let effective = effective_priority_edges(facts, explicit)?;
    validate_acyclic_edges(&goals, &effective, "effective priority order")
}

fn validate_goal_hierarchy(facts: &TribleSet, goals: &BTreeSet<Id>) -> Result<()> {
    validate_acyclic_edges(goals, &parent_edges(facts)?, "goal parent hierarchy")
}

fn ensure_status_intrinsic(snapshot: &StatusSnapshot) -> Result<TribleSet> {
    ensure_intrinsic(
        snapshot.id,
        status_record(
            snapshot.goal,
            &snapshot.value,
            &snapshot.predecessors,
            snapshot.by,
            snapshot.created_at,
        ),
        "status snapshot",
    )
    .and_then(|expected| {
        match canonical_status(snapshot.value.clone()) {
            Ok(value) if value == snapshot.value => {}
            _ => bail!(
                "status snapshot {:x} has a non-canonical value",
                snapshot.id
            ),
        }
        point_interval(snapshot.created_at, "status creation time")?;
        Ok(expected)
    })
}

fn validate_priority_snapshot_intrinsic(facts: &TribleSet, id: Id) -> Result<PrioritySnapshot> {
    let edge_ids = sorted_ids(find!(
        value: Id,
        pattern!(facts, [{ id @ priority::edge: ?value }])
    ));
    let mut edges = BTreeSet::new();
    for edge_id in &edge_ids {
        let edge = priority_edge(facts, *edge_id)?;
        let _ = ensure_intrinsic(
            *edge_id,
            priority_edge_record(edge.higher, edge.lower),
            "priority edge",
        )?;
        edges.insert((edge.higher, edge.lower));
    }
    validate_priority_edges(facts, &edges)?;
    let predecessors = sorted_ids(find!(
        value: Id,
        pattern!(facts, [{ id @ metadata::supersedes: ?value }])
    ));
    let _ = ensure_intrinsic(
        id,
        priority_snapshot_record(&edge_ids, &predecessors),
        "priority snapshot",
    )?;
    Ok(PrioritySnapshot {
        id,
        edges,
        predecessors,
    })
}

#[derive(Clone, Copy)]
enum TextRule {
    Any,
    RequiredCanonical,
    CanonicalTag,
}

fn validate_structure(facts: &TribleSet) -> Result<Vec<(TextHandle, TextRule)>> {
    let goals = goal_anchors(facts);
    let genesis_ids = ids_of_kind(facts, KIND_GOAL_GENESIS);
    let note_ids = ids_of_kind(facts, KIND_NOTE);
    let status_ids = ids_of_kind(facts, KIND_STATUS_SNAPSHOT);
    let priority_snapshot_ids = ids_of_kind(facts, KIND_PRIORITY_SNAPSHOT);
    let priority_edge_ids = ids_of_kind(facts, KIND_PRIORITY_EDGE);
    let tag_ids = tag_ids(facts);

    let mut expected = TribleSet::new();
    let mut texts = Vec::new();
    let mut referenced_tags = BTreeSet::new();
    for &goal_id in &goals {
        expected += goal_anchor_record(goal_id);
    }

    for &id in &tag_ids {
        let record = tag_record(facts, id)?;
        texts.push((record.name, TextRule::CanonicalTag));
        expected += ensure_intrinsic(id, tag_record_fragment(record.name), "Compass tag")?;
    }

    let mut genesis_by_goal: BTreeMap<Id, Vec<Id>> = BTreeMap::new();
    for id in genesis_ids {
        let genesis = goal_genesis(facts, id)?;
        if !goals.contains(&genesis.goal) {
            bail!(
                "goal genesis {id:x} names undeclared goal {:x}",
                genesis.goal
            );
        }
        point_interval(genesis.created_at, "goal creation time")?;
        for tag in &genesis.tags {
            if !tag_ids.contains(tag) {
                bail!("goal genesis {id:x} cites unknown tag {tag:x}");
            }
            referenced_tags.insert(*tag);
        }
        if genesis.parent == Some(genesis.goal) {
            bail!("goal {:x} is its own parent", genesis.goal);
        }
        if let Some(parent) = genesis.parent {
            if !goals.contains(&parent) {
                bail!("goal {:x} names undeclared parent {parent:x}", genesis.goal);
            }
        }
        texts.push((genesis.title, TextRule::RequiredCanonical));
        expected += ensure_intrinsic(
            id,
            goal_genesis_record(
                genesis.goal,
                genesis.title,
                &genesis.tags,
                genesis.parent,
                genesis.created_at,
            ),
            "goal genesis",
        )?;
        genesis_by_goal.entry(genesis.goal).or_default().push(id);
    }
    for &goal_id in &goals {
        match genesis_by_goal.get(&goal_id).map(Vec::len) {
            Some(1) => {}
            Some(count) => bail!("goal {goal_id:x} has {count} genesis records"),
            None => bail!("goal {goal_id:x} has no genesis record"),
        }
    }
    validate_goal_hierarchy(facts, &goals)?;

    let mut notes_by_goal: BTreeMap<Id, BTreeMap<Id, Vec<Id>>> = BTreeMap::new();
    let note_id_set = note_ids.clone();
    for id in note_ids {
        let record = note_record(facts, id)?;
        if !goals.contains(&record.goal) {
            bail!("note {id:x} names undeclared goal {:x}", record.goal);
        }
        point_interval(record.created_at, "note creation time")?;
        for tag in &record.tags {
            if !tag_ids.contains(tag) {
                bail!("note {id:x} cites unknown tag {tag:x}");
            }
            referenced_tags.insert(*tag);
        }
        texts.push((record.body, TextRule::Any));
        texts.extend(
            record
                .references
                .iter()
                .copied()
                .map(|handle| (handle, TextRule::RequiredCanonical)),
        );
        for predecessor in &record.supersedes {
            if !note_id_set.contains(predecessor) {
                bail!("note {id:x} supersedes missing note {predecessor:x}");
            }
            let predecessor_record = note_record(facts, *predecessor)?;
            if predecessor_record.goal != record.goal {
                bail!("note {id:x} supersedes a note on another goal");
            }
        }
        notes_by_goal
            .entry(record.goal)
            .or_default()
            .insert(id, record.supersedes.clone());
        expected += ensure_intrinsic(
            id,
            note_record_fragment(
                record.occurrence,
                record.goal,
                record.body,
                &record.tags,
                &record.references,
                &record.supersedes,
                record.by,
                record.created_at,
            ),
            "note",
        )?;
    }
    for (goal_id, graph) in notes_by_goal {
        let _ = dag_heads(&graph, &format!("note provenance for goal {goal_id:x}"))?;
    }
    if referenced_tags != tag_ids {
        let orphan = tag_ids.difference(&referenced_tags).next().unwrap();
        bail!("Compass tag {orphan:x} is not attached to a goal or note");
    }

    let mut statuses_by_goal: BTreeMap<Id, BTreeMap<Id, Vec<Id>>> = BTreeMap::new();
    for id in status_ids {
        let snapshot = status_snapshot(facts, id)?;
        if !goals.contains(&snapshot.goal) {
            bail!(
                "status snapshot {id:x} names undeclared goal {:x}",
                snapshot.goal
            );
        }
        expected += ensure_status_intrinsic(&snapshot)?;
        statuses_by_goal
            .entry(snapshot.goal)
            .or_default()
            .insert(id, snapshot.predecessors.clone());
    }
    for &goal_id in &goals {
        let graph = statuses_by_goal
            .get(&goal_id)
            .ok_or_else(|| anyhow!("goal {goal_id:x} has no status snapshot"))?;
        let _ = dag_heads(graph, &format!("status track for goal {goal_id:x}"))?;
    }

    let mut edge_records = BTreeMap::new();
    for id in priority_edge_ids {
        let edge = priority_edge(facts, id)?;
        let record = priority_edge_record(edge.higher, edge.lower);
        expected += ensure_intrinsic(id, record, "priority edge")?;
        edge_records.insert(id, edge);
    }

    let mut priority_graph = BTreeMap::new();
    let mut referenced_edges = BTreeSet::new();
    for id in priority_snapshot_ids {
        let edge_ids = sorted_ids(find!(
            value: Id,
            pattern!(facts, [{ id @ priority::edge: ?value }])
        ));
        let mut edges = BTreeSet::new();
        for edge_id in &edge_ids {
            let edge = edge_records.get(edge_id).ok_or_else(|| {
                anyhow!("priority snapshot {id:x} cites missing edge {edge_id:x}")
            })?;
            edges.insert((edge.higher, edge.lower));
            referenced_edges.insert(*edge_id);
        }
        validate_priority_edges(facts, &edges)
            .with_context(|| format!("validate priority snapshot {id:x}"))?;
        let snapshot = PrioritySnapshot {
            id,
            edges,
            predecessors: sorted_ids(find!(
                value: Id,
                pattern!(facts, [{ id @ metadata::supersedes: ?value }])
            )),
        };
        expected += ensure_intrinsic(
            id,
            priority_snapshot_record(&edge_ids, &snapshot.predecessors),
            "priority snapshot",
        )?;
        priority_graph.insert(id, snapshot.predecessors);
    }
    if !goals.is_empty() && priority_graph.is_empty() {
        bail!("non-empty Compass board has no priority snapshot");
    }
    let _ = dag_heads(&priority_graph, "priority snapshot")?;
    if referenced_edges.len() != edge_records.len() {
        let stray = edge_records
            .keys()
            .find(|id| !referenced_edges.contains(*id))
            .unwrap();
        bail!("priority edge {stray:x} is not referenced by any snapshot");
    }

    if expected != *facts {
        let missing = expected.difference(facts).len();
        let unexpected = facts.difference(&expected).len();
        bail!(
            "Compass catalog is not an exact canonical ontology ({missing} missing, {unexpected} unexpected facts)"
        );
    }
    Ok(texts)
}

fn load_text_from(reader: &PileReader, handle: TextHandle) -> Result<String> {
    let view: View<str> = reader
        .get(handle)
        .with_context(|| format!("read Compass text payload {}", hex::encode(handle.raw)))?;
    Ok(view.to_string())
}

fn load_text_overlay<Overlay>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    handle: TextHandle,
) -> Result<String>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    if let Some(overlay) = overlay {
        if overlay
            .metadata(handle)
            .expect("memory metadata lookup is infallible")
            .is_some()
        {
            let view: View<str> = overlay.get(handle).with_context(|| {
                format!(
                    "read staged Compass text payload {}",
                    hex::encode(handle.raw)
                )
            })?;
            return Ok(view.to_string());
        }
    }
    load_text_from(reader, handle)
}

fn validate_texts<Overlay>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    handles: Vec<(TextHandle, TextRule)>,
) -> Result<()>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    let mut seen = HashMap::new();
    for (handle, rule) in handles {
        seen.entry(handle.raw)
            .and_modify(|existing| {
                if matches!(rule, TextRule::CanonicalTag)
                    || matches!(
                        (rule, *existing),
                        (TextRule::RequiredCanonical, TextRule::Any)
                    )
                {
                    *existing = rule;
                }
            })
            .or_insert(rule);
    }
    for (raw, rule) in seen {
        let handle = Inline::new(raw);
        let value = load_text_overlay(reader, overlay, handle)?;
        if value.bytes().any(|byte| byte == 0) {
            bail!("Compass text payload contains a NUL byte");
        }
        if matches!(rule, TextRule::RequiredCanonical | TextRule::CanonicalTag)
            && (value.is_empty() || value.trim() != value)
        {
            bail!("Compass canonical text payload is empty or has surrounding whitespace");
        }
        if matches!(rule, TextRule::CanonicalTag) && canonical_tag(value.clone())? != value {
            bail!("Compass tag payload is not normalized: {value:?}");
        }
    }
    Ok(())
}

/// Validate the complete materialized authored Compass collection. Forks are
/// valid values; malformed records, invalid individual snapshots, and missing
/// attachments are not.
pub fn validate_catalog(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    let texts = validate_structure(facts)?;
    validate_texts(reader, None::<&PileReader>, texts)
}

/// Preflight the exact set union that publication would create, reading staged
/// attachments from the fragment without writing pile bytes.
pub fn validate_catalog_union(
    reader: &PileReader,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<TribleSet> {
    let mut expected = current.clone();
    expected += fragment.facts().clone();
    let texts = validate_structure(&expected)?;
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .reader()
        .expect("MemoryBlobStore reader creation is infallible");
    validate_texts(reader, Some(&overlay), texts)?;
    Ok(expected)
}

pub fn read_text(reader: &PileReader, handle: TextHandle) -> Result<String> {
    load_text_from(reader, handle)
}

pub fn tag_label(reader: &PileReader, facts: &TribleSet, id: Id) -> Result<String> {
    read_text(reader, tag_record(facts, id)?.name)
}

pub fn tag_labels(reader: &PileReader, facts: &TribleSet, ids: &[Id]) -> Result<Vec<String>> {
    let mut labels = ids
        .iter()
        .map(|id| tag_label(reader, facts, *id))
        .collect::<Result<Vec<_>>>()?;
    labels.sort();
    labels.dedup();
    Ok(labels)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::path::PathBuf;

    use crate::collection_access;
    use crate::schemas::compass::DEFAULT_SCOPE_ID;
    use ed25519_dalek::VerifyingKey;
    use hifitime::Epoch;
    use std::collections::HashSet;

    fn at(second: u8) -> IntervalValue {
        let epoch = Epoch::from_gregorian_utc(2026, 8, 8, 0, 0, second, 0);
        (epoch, epoch).try_to_inline().unwrap()
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        pile: PathBuf,
        key: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let pile = directory.path().join("compass.pile");
            let key = directory.path().join("compass.key");
            File::create(&pile).unwrap();
            collection_access::initialize_signer(&pile, Some(&key)).unwrap();
            Self {
                _directory: directory,
                pile,
                key,
            }
        }

        fn publish(&self, fragment: Fragment) {
            collection_access::publish_fragment(
                &self.pile,
                Some(&self.key),
                DEFAULT_SCOPE_ID,
                fragment,
                Fragment::empty(),
            )
            .unwrap();
        }

        fn view(&self) -> collection_access::CollectionView {
            let signer = collection_access::load_signer(&self.pile, Some(&self.key)).unwrap();
            let allowed: HashSet<VerifyingKey> = HashSet::from([signer.verifying_key()]);
            collection_access::materialize_scope(&self.pile, DEFAULT_SCOPE_ID, &allowed).unwrap()
        }
    }

    fn publish_goal(fixture: &Fixture, goal_id: Id, title: &str, parent: Option<Id>) {
        let (mut fragment, _, _) =
            goal_fragment(goal_id, title, vec![], parent, "todo", None, at(0)).unwrap();
        fragment += priority_snapshot_fragment([], &[]).unwrap().0;
        fixture.publish(fragment);
    }

    fn status_heads(resolution: StatusResolution) -> Vec<Id> {
        resolution.head_ids()
    }

    #[test]
    fn status_identity_is_canonical_and_predecessor_order_independent() {
        let goal_id = genid().id;
        let a = genid().id;
        let b = genid().id;
        let first = status_fragment(goal_id, " Doing ", &[b, a, b], None, at(1)).unwrap();
        let second = status_fragment(goal_id, "doing", &[a, b], None, at(1)).unwrap();
        assert_eq!(first.root(), second.root());
    }

    #[test]
    fn tag_and_goal_genesis_identity_use_normalized_set_semantics() {
        let (_, first_tag, first_label) = tag_fragment(" #Later ").unwrap();
        let (_, second_tag, second_label) = tag_fragment("later").unwrap();
        assert_eq!(first_label, "later");
        assert_eq!(first_label, second_label);
        assert_eq!(first_tag, second_tag);

        let goal_id = genid().id;
        let (_, first_genesis, _) = goal_fragment(
            goal_id,
            "One",
            vec!["Later".into(), "#research".into(), "later".into()],
            None,
            "todo",
            None,
            at(0),
        )
        .unwrap();
        let (_, second_genesis, _) = goal_fragment(
            goal_id,
            "One",
            vec!["research".into(), "later".into()],
            None,
            "todo",
            None,
            at(0),
        )
        .unwrap();
        assert_eq!(first_genesis, second_genesis);
    }

    #[test]
    fn concurrent_statuses_are_visible_and_move_can_join_every_head() {
        let fixture = Fixture::new();
        let goal_id = genid().id;
        publish_goal(&fixture, goal_id, "One", None);
        let view = fixture.view();
        let initial = status_heads(status_resolution(&view.facts, goal_id))[0];
        fixture.publish(status_fragment(goal_id, "doing", &[initial], None, at(1)).unwrap());
        fixture.publish(status_fragment(goal_id, "blocked", &[initial], None, at(2)).unwrap());
        let view = fixture.view();
        let heads = status_heads(status_resolution(&view.facts, goal_id));
        assert_eq!(heads.len(), 2);
        fixture.publish(status_fragment(goal_id, "done", &heads, None, at(3)).unwrap());
        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        assert!(matches!(
            status_resolution(&view.facts, goal_id),
            StatusResolution::Unique(StatusSnapshot { value, .. }) if value == "done"
        ));
    }

    #[test]
    fn equal_concurrent_status_events_remain_distinct_but_resolve_as_agreement() {
        let fixture = Fixture::new();
        let goal_id = genid().id;
        publish_goal(&fixture, goal_id, "One", None);
        let view = fixture.view();
        let initial = status_resolution(&view.facts, goal_id).head_ids()[0];

        let first = status_fragment(goal_id, "doing", &[initial], None, at(1)).unwrap();
        let second = status_fragment(goal_id, "doing", &[initial], None, at(2)).unwrap();
        assert_ne!(first.root(), second.root());
        fixture.publish(first);
        fixture.publish(second);

        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        let resolution = status_resolution(&view.facts, goal_id);
        let heads = resolution.head_ids();
        assert!(matches!(
            resolution,
            StatusResolution::Agreed(ref snapshots)
                if snapshots.len() == 2
                    && snapshots.iter().all(|snapshot| snapshot.value == "doing")
        ));

        fixture.publish(status_fragment(goal_id, "doing", &heads, None, at(3)).unwrap());
        let view = fixture.view();
        assert!(matches!(
            status_resolution(&view.facts, goal_id),
            StatusResolution::Unique(StatusSnapshot { value, predecessors, .. })
                if value == "doing" && predecessors == heads
        ));
    }

    #[test]
    fn board_snapshot_prevents_cross_replica_cycle_from_becoming_one_state() {
        let fixture = Fixture::new();
        let a = genid().id;
        let b = genid().id;
        let c = genid().id;
        publish_goal(&fixture, a, "A", None);
        publish_goal(&fixture, b, "B", None);
        publish_goal(&fixture, c, "C", None);
        let view = fixture.view();
        let initial = priority_resolution(&view.facts).head_ids()[0];
        fixture.publish(
            priority_snapshot_fragment([(a, b), (b, c)], &[initial])
                .unwrap()
                .0,
        );
        fixture.publish(priority_snapshot_fragment([(c, a)], &[initial]).unwrap().0);
        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        assert!(matches!(
            priority_resolution(&view.facts),
            PriorityResolution::Forked(ref snapshots) if snapshots.len() == 2
        ));
        assert!(explicit_priority_edges(&view.facts).is_err());

        let cyclic = BTreeSet::from([(a, b), (b, c), (c, a)]);
        assert!(validate_priority_edges(&view.facts, &cyclic).is_err());
    }

    #[test]
    fn explicit_priority_reconciliation_names_all_heads() {
        let fixture = Fixture::new();
        let a = genid().id;
        let b = genid().id;
        let c = genid().id;
        publish_goal(&fixture, a, "A", None);
        publish_goal(&fixture, b, "B", None);
        publish_goal(&fixture, c, "C", None);
        let view = fixture.view();
        let initial = priority_resolution(&view.facts).head_ids()[0];
        fixture.publish(priority_snapshot_fragment([(a, b)], &[initial]).unwrap().0);
        fixture.publish(priority_snapshot_fragment([(a, c)], &[initial]).unwrap().0);
        let view = fixture.view();
        let heads = priority_resolution(&view.facts).head_ids();
        assert_eq!(heads.len(), 2);
        fixture.publish(
            priority_snapshot_fragment([(a, b), (a, c)], &heads)
                .unwrap()
                .0,
        );
        let view = fixture.view();
        assert!(matches!(
            priority_resolution(&view.facts),
            PriorityResolution::Unique(PrioritySnapshot { edges, .. })
                if edges == BTreeSet::from([(a, b), (a, c)])
        ));
    }

    #[test]
    fn equal_priority_heads_keep_history_but_expose_the_common_edge_set() {
        let fixture = Fixture::new();
        let a = genid().id;
        let b = genid().id;
        publish_goal(&fixture, a, "A", None);
        publish_goal(&fixture, b, "B", None);
        let view = fixture.view();
        let initial = priority_resolution(&view.facts).head_ids()[0];

        let (first, first_id) = priority_snapshot_fragment([(a, b)], &[initial]).unwrap();
        let (second, second_id) = priority_snapshot_fragment([(b, a)], &[initial]).unwrap();
        fixture.publish(first);
        fixture.publish(second);

        // Independent histories converge on the same complete edge set while
        // citing different predecessors, so the records remain distinct.
        let (first_convergence, first_convergence_id) =
            priority_snapshot_fragment([(a, b)], &[first_id]).unwrap();
        let (second_convergence, second_convergence_id) =
            priority_snapshot_fragment([(a, b)], &[second_id]).unwrap();
        assert_ne!(first_convergence_id, second_convergence_id);
        fixture.publish(first_convergence);
        fixture.publish(second_convergence);

        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        let resolution = priority_resolution(&view.facts);
        let heads = resolution.head_ids();
        assert!(matches!(
            resolution,
            PriorityResolution::Agreed(ref snapshots)
                if snapshots.len() == 2
                    && snapshots.iter().all(|snapshot| snapshot.edges == BTreeSet::from([(a, b)]))
        ));
        assert_eq!(
            explicit_priority_edges(&view.facts).unwrap(),
            BTreeSet::from([(a, b)])
        );

        fixture.publish(priority_snapshot_fragment([(b, a)], &heads).unwrap().0);
        let view = fixture.view();
        assert!(matches!(
            priority_resolution(&view.facts),
            PriorityResolution::Unique(PrioritySnapshot { edges, predecessors, .. })
                if edges == BTreeSet::from([(b, a)]) && predecessors == heads
        ));
    }

    #[test]
    fn note_occurrences_do_not_collapse_and_supersedes_is_only_provenance() {
        let fixture = Fixture::new();
        let goal_id = genid().id;
        publish_goal(&fixture, goal_id, "One", None);
        let (first_fragment, first) = note_fragment(
            genid().id,
            goal_id,
            "same",
            vec![],
            vec![],
            &[],
            None,
            at(1),
        )
        .unwrap();
        fixture.publish(first_fragment);
        let (second_fragment, second) = note_fragment(
            genid().id,
            goal_id,
            "same",
            vec![],
            vec![],
            &[first],
            None,
            at(1),
        )
        .unwrap();
        assert_ne!(first, second);
        fixture.publish(second_fragment);
        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        let notes = notes_for_goal(&view.facts, goal_id).unwrap();
        assert_eq!(notes.len(), 2);

        let (mut accretion, tag, _) = tag_fragment("later").unwrap();
        accretion += entity! { ExclusiveId::force_ref(&first) @ metadata::tag: &tag };
        let error = validate_catalog_union(&view.reader, &view.facts, &accretion).unwrap_err();
        assert!(
            format!("{error:#}").contains("note")
                && format!("{error:#}").contains("does not match intrinsic root")
        );
    }

    #[test]
    fn exact_catalog_rejects_extra_facts_and_preflight_reads_staged_text() {
        let fixture = Fixture::new();
        let view = fixture.view();
        let goal_id = genid().id;
        let (mut fragment, _, _) = goal_fragment(
            goal_id,
            "A title longer than an inline value",
            vec!["later".into()],
            None,
            "todo",
            None,
            at(0),
        )
        .unwrap();
        fragment += priority_snapshot_fragment([], &[]).unwrap().0;
        let union = validate_catalog_union(&view.reader, &view.facts, &fragment).unwrap();
        assert!(goal_anchors(&union).contains(&goal_id));

        fixture.publish(fragment);
        let view = fixture.view();
        let genesis = genesis_for_goal(&view.facts, goal_id).unwrap().unwrap();
        let mut malformed = view.facts.clone();
        malformed +=
            entity! { ExclusiveId::force_ref(&genesis.id) @ metadata::description: genesis.title };
        assert!(validate_catalog(&view.reader, &malformed).is_err());
    }

    #[test]
    fn catalog_rejects_unknown_and_non_intrinsic_tag_entities() {
        let fixture = Fixture::new();
        let view = fixture.view();
        let goal_id = genid().id;
        let unknown_tag = genid().id;
        let created_at = at(0);

        let mut unknown = Fragment::empty();
        let title = unknown.put("One".to_owned());
        unknown += goal_anchor_record(goal_id);
        unknown += goal_genesis_record(goal_id, title, &[unknown_tag], None, created_at);
        unknown += status_fragment(goal_id, "todo", &[], None, created_at).unwrap();
        unknown += priority_snapshot_fragment([], &[]).unwrap().0;
        let error = validate_catalog_union(&view.reader, &view.facts, &unknown).unwrap_err();
        assert!(format!("{error:#}").contains("unknown tag"));

        let mut malformed = unknown;
        let name = malformed.put("fake".to_owned());
        malformed += entity! { ExclusiveId::force_ref(&unknown_tag) @
            metadata::tag: &KIND_TAG,
            metadata::name: name,
        };
        let error = validate_catalog_union(&view.reader, &view.facts, &malformed).unwrap_err();
        assert!(format!("{error:#}").contains("does not match intrinsic root"));

        let other_goal = genid().id;
        let mut noncanonical = Fragment::empty();
        let name = noncanonical.put("MixedCase".to_owned());
        let tag = tag_record_fragment(name);
        let tag_id = tag.root().unwrap();
        noncanonical += tag;
        let title = noncanonical.put("Other".to_owned());
        noncanonical += goal_anchor_record(other_goal);
        noncanonical += goal_genesis_record(other_goal, title, &[tag_id], None, created_at);
        noncanonical += status_fragment(other_goal, "todo", &[], None, created_at).unwrap();
        noncanonical += priority_snapshot_fragment([], &[]).unwrap().0;
        let error = validate_catalog_union(&view.reader, &view.facts, &noncanonical).unwrap_err();
        assert!(format!("{error:#}").contains("not normalized"));
    }

    #[test]
    fn typed_status_resolution_reports_non_intrinsic_state_as_invalid() {
        let goal_id = genid().id;
        let (mut fragment, _, initial) =
            goal_fragment(goal_id, "One", vec![], None, "todo", None, at(0)).unwrap();
        fragment += priority_snapshot_fragment([], &[]).unwrap().0;
        let fake = genid().id;
        fragment += entity! { ExclusiveId::force_ref(&fake) @
            metadata::tag: &KIND_STATUS_SNAPSHOT,
            status::of: &goal_id,
            status::value: "doing",
            metadata::supersedes: &initial,
            metadata::created_at: at(1),
        };
        assert!(matches!(
            status_resolution(fragment.facts(), goal_id),
            StatusResolution::Invalid(_)
        ));
    }

    #[test]
    fn parent_edges_are_immutable_priority_constraints() {
        let fixture = Fixture::new();
        let parent = genid().id;
        let child = genid().id;
        publish_goal(&fixture, parent, "Parent", None);
        publish_goal(&fixture, child, "Child", Some(parent));
        let view = fixture.view();
        assert!(validate_priority_edges(&view.facts, &BTreeSet::from([(parent, child)])).is_err());
    }
}
