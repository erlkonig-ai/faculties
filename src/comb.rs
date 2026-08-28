//! Canonical persona-scoped cursor DAG for Memory practices.
//!
//! A cursor snapshot is an immutable state on the `(stream, persona)` track.
//! Its direct `metadata::supersedes` antichain is part of intrinsic identity;
//! observation times are additive exhaust.  Concurrent advances therefore
//! remain visible as a fork, and a later snapshot can reconcile them by naming
//! every live head without any last-write-wins clock.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Result};
use triblespace::core::metadata;
use triblespace::prelude::*;

use crate::schemas::memory::comb::{
    cursor_anchor, cursor_grain, cursor_persona, cursor_position, cursor_stream, kind_comb_cursor,
};

pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

fn ancestors(graph: &BTreeMap<Id, BTreeSet<Id>>, start: Id) -> BTreeSet<Id> {
    let mut found = BTreeSet::new();
    let mut pending: Vec<Id> = graph
        .get(&start)
        .into_iter()
        .flat_map(|values| values.iter().copied())
        .collect();
    while let Some(node) = pending.pop() {
        if found.insert(node) {
            pending.extend(
                graph
                    .get(&node)
                    .into_iter()
                    .flat_map(|values| values.iter().copied()),
            );
        }
    }
    found
}

fn validate_predecessor_dag(graph: &BTreeMap<Id, BTreeSet<Id>>, label: &str) -> Result<()> {
    for (node, predecessors) in graph {
        for predecessor in predecessors {
            if !graph.contains_key(predecessor) {
                bail!("{label} node {node:x} supersedes missing node {predecessor:x}");
            }
        }
    }

    let mut remaining: BTreeMap<Id, usize> = graph
        .iter()
        .map(|(node, predecessors)| (*node, predecessors.len()))
        .collect();
    let mut successors: BTreeMap<Id, Vec<Id>> = BTreeMap::new();
    for (node, predecessors) in graph {
        for predecessor in predecessors {
            successors.entry(*predecessor).or_default().push(*node);
        }
    }
    let mut ready: Vec<Id> = remaining
        .iter()
        .filter_map(|(node, count)| (*count == 0).then_some(*node))
        .collect();
    let mut ordered = 0usize;
    while let Some(node) = ready.pop() {
        ordered += 1;
        for successor in successors.get(&node).into_iter().flatten() {
            let count = remaining
                .get_mut(successor)
                .expect("successor has dependency count");
            *count -= 1;
            if *count == 0 {
                ready.push(*successor);
            }
        }
    }
    if ordered != graph.len() {
        bail!("{label} supersedes graph contains a cycle");
    }

    for (node, predecessors) in graph {
        let predecessors: Vec<Id> = predecessors.iter().copied().collect();
        for (index, left) in predecessors.iter().enumerate() {
            let left_ancestors = ancestors(graph, *left);
            for right in &predecessors[index + 1..] {
                let right_ancestors = ancestors(graph, *right);
                if left_ancestors.contains(right) || right_ancestors.contains(left) {
                    bail!(
                        "{label} node {node:x} has non-antichain predecessors {left:x} and {right:x}"
                    );
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CursorTrack {
    pub stream: String,
    pub persona: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CursorState {
    /// `None` is an explicit stopped state.
    pub position: Option<IntervalValue>,
    /// Exact item consumed at `position` when timestamp alone is ambiguous.
    pub anchor: Option<Id>,
    /// Present only for active practices whose next read needs a grain.
    pub grain: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CursorRow {
    pub id: Id,
    pub track: CursorTrack,
    pub state: CursorState,
    pub predecessors: BTreeSet<Id>,
    pub observed_at: BTreeSet<IntervalValue>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CursorResolution {
    Unique(CursorRow),
    Agreed(Vec<CursorRow>),
    Forked(Vec<CursorRow>),
}

impl CursorResolution {
    pub fn head_ids(&self) -> Vec<Id> {
        match self {
            Self::Unique(row) => vec![row.id],
            Self::Agreed(rows) | Self::Forked(rows) => rows.iter().map(|row| row.id).collect(),
        }
    }

    pub fn settled_state(&self) -> Result<&CursorState> {
        match self {
            Self::Unique(row) => Ok(&row.state),
            Self::Agreed(rows) => Ok(&rows[0].state),
            Self::Forked(rows) => bail!(
                "comb cursor is forked across heads {}",
                rows.iter()
                    .map(|row| format!("{:x}", row.id))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CombCatalog {
    pub cursors: BTreeMap<Id, CursorRow>,
    tracks: BTreeMap<CursorTrack, CursorResolution>,
}

impl CombCatalog {
    pub fn resolution(&self, stream: &str, persona: &str) -> Option<&CursorResolution> {
        self.tracks.get(&CursorTrack {
            stream: stream.to_owned(),
            persona: persona.to_owned(),
        })
    }

    pub fn tracks(&self) -> impl Iterator<Item = (&CursorTrack, &CursorResolution)> {
        self.tracks.iter()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CursorDraft {
    pub stream: String,
    pub persona: String,
    pub position: Option<IntervalValue>,
    pub anchor: Option<Id>,
    pub grain: Option<String>,
    pub predecessors: BTreeSet<Id>,
    pub observed_at: BTreeSet<IntervalValue>,
}

fn validate_short(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.trim() != value {
        bail!("{field} must be non-empty and have no surrounding whitespace");
    }
    if value.len() > 32 {
        bail!("{field} exceeds 32 UTF-8 bytes");
    }
    if value.as_bytes().contains(&0) {
        bail!("{field} contains a NUL byte");
    }
    Ok(())
}

fn point(entity: Option<Id>, field: &str, value: IntervalValue) -> Result<()> {
    let (lower, upper): (i128, i128) = value.try_from_inline().map_err(|error| match entity {
        Some(id) => anyhow!("decode {field} on comb cursor {id:x}: {error:?}"),
        None => anyhow!("decode {field}: {error:?}"),
    })?;
    if lower != upper {
        match entity {
            Some(id) => bail!("{field} on comb cursor {id:x} must be a point interval"),
            None => bail!("{field} must be a point interval"),
        }
    }
    Ok(())
}

fn one_required<T: Ord>(mut values: BTreeSet<T>, id: Id, field: &str) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "comb cursor {id:x} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(values.pop_first().expect("length checked"))
}

fn one<T: Ord>(mut values: BTreeSet<T>, id: Id, field: &str) -> Result<Option<T>> {
    if values.len() > 1 {
        bail!(
            "comb cursor {id:x} has {} values for {field}; expected at most one",
            values.len()
        );
    }
    Ok(values.pop_first())
}

fn cursor_core(track: &CursorTrack, state: &CursorState, predecessors: &BTreeSet<Id>) -> Fragment {
    entity! {
        metadata::tag: &kind_comb_cursor,
        cursor_stream: track.stream.as_str(),
        cursor_persona: track.persona.as_str(),
        cursor_position?: state.position.as_ref(),
        cursor_anchor?: state.anchor.as_ref(),
        cursor_grain?: state.grain.as_deref(),
        metadata::supersedes*: predecessors.iter(),
    }
}

fn cursor_record(row: &CursorRow) -> Fragment {
    let mut fragment = cursor_core(&row.track, &row.state, &row.predecessors);
    let id = fragment
        .root()
        .expect("canonical comb cursor core has one intrinsic root");
    for at in &row.observed_at {
        fragment += entity! { ExclusiveId::force_ref(&id) @ metadata::created_at: at };
    }
    fragment
}

pub fn cursor_fragment(draft: CursorDraft) -> Result<(Fragment, Id)> {
    validate_short("cursor stream", &draft.stream)?;
    validate_short("cursor persona", &draft.persona)?;
    if let Some(position) = draft.position {
        point(None, "cursor position", position)?;
    } else if draft.grain.is_some() || draft.anchor.is_some() {
        bail!("a stopped cursor cannot retain a grain or anchor");
    }
    if let Some(grain) = &draft.grain {
        validate_short("cursor grain", grain)?;
    }
    for at in &draft.observed_at {
        point(None, "cursor observation time", *at)?;
    }
    let track = CursorTrack {
        stream: draft.stream,
        persona: draft.persona,
    };
    let state = CursorState {
        position: draft.position,
        anchor: draft.anchor,
        grain: draft.grain,
    };
    let mut fragment = cursor_core(&track, &state, &draft.predecessors);
    let id = fragment
        .root()
        .ok_or_else(|| anyhow!("comb cursor fragment has no unique intrinsic root"))?;
    for at in &draft.observed_at {
        fragment += entity! { ExclusiveId::force_ref(&id) @ metadata::created_at: at };
    }
    Ok((fragment, id))
}

fn entity_facts(space: &TribleSet, entity: Id) -> TribleSet {
    let mut facts = TribleSet::new();
    for fact in space.iter().filter(|fact| fact.e() == &entity) {
        facts.insert(fact);
    }
    facts
}

fn load_cursor(space: &TribleSet, id: Id) -> Result<CursorRow> {
    let row = CursorRow {
        id,
        track: CursorTrack {
            stream: one_required(
                find!(value: String, pattern!(space, [{ id @ cursor_stream: ?value }])).collect(),
                id,
                "cursor_stream",
            )?,
            persona: one_required(
                find!(value: String, pattern!(space, [{ id @ cursor_persona: ?value }])).collect(),
                id,
                "cursor_persona",
            )?,
        },
        state: CursorState {
            position: one(
                find!(value: IntervalValue, pattern!(space, [{ id @ cursor_position: ?value }]))
                    .collect(),
                id,
                "cursor_position",
            )?,
            anchor: one(
                find!(value: Id, pattern!(space, [{ id @ cursor_anchor: ?value }])).collect(),
                id,
                "cursor_anchor",
            )?,
            grain: one(
                find!(value: String, pattern!(space, [{ id @ cursor_grain: ?value }])).collect(),
                id,
                "cursor_grain",
            )?,
        },
        predecessors: find!(value: Id, pattern!(space, [{ id @ metadata::supersedes: ?value }]))
            .collect(),
        observed_at:
            find!(value: IntervalValue, pattern!(space, [{ id @ metadata::created_at: ?value }]))
                .collect(),
    };
    validate_short("cursor stream", &row.track.stream)?;
    validate_short("cursor persona", &row.track.persona)?;
    if let Some(position) = row.state.position {
        point(Some(id), "cursor position", position)?;
    } else if row.state.grain.is_some() || row.state.anchor.is_some() {
        bail!("stopped comb cursor {id:x} retains a grain or anchor");
    }
    if let Some(grain) = &row.state.grain {
        validate_short("cursor grain", grain)?;
    }
    for at in &row.observed_at {
        point(Some(id), "cursor observation time", *at)?;
    }
    let canonical = cursor_core(&row.track, &row.state, &row.predecessors)
        .root()
        .expect("cursor core has one root");
    if canonical != id {
        bail!("comb cursor {id:x} does not match intrinsic core {canonical:x}");
    }
    if entity_facts(space, id) != *cursor_record(&row).facts() {
        bail!("comb cursor {id:x} is not one canonical immutable record");
    }
    Ok(row)
}

/// Strictly project the complete Comb collection and expose every track fork.
pub fn load_catalog(space: &TribleSet) -> Result<CombCatalog> {
    let ids: BTreeSet<Id> = find!(
        id: Id,
        pattern!(space, [{ ?id @ metadata::tag: &kind_comb_cursor }])
    )
    .collect();
    let mut cursors = BTreeMap::new();
    for id in &ids {
        cursors.insert(*id, load_cursor(space, *id)?);
    }

    let graph: BTreeMap<Id, BTreeSet<Id>> = cursors
        .values()
        .map(|row| (row.id, row.predecessors.clone()))
        .collect();
    validate_predecessor_dag(&graph, "Comb cursor")?;
    for row in cursors.values() {
        for predecessor in &row.predecessors {
            let prior = &cursors[predecessor];
            if prior.track != row.track {
                bail!(
                    "comb cursor {:x} on ({}, {}) supersedes cursor {predecessor:x} on ({}, {})",
                    row.id,
                    row.track.stream,
                    row.track.persona,
                    prior.track.stream,
                    prior.track.persona
                );
            }
        }
    }

    let accounted: usize = ids.iter().map(|id| entity_facts(space, *id).len()).sum();
    if accounted != space.len() {
        bail!(
            "Comb collection has {} facts outside canonical cursor records",
            space.len() - accounted.min(space.len())
        );
    }

    let mut by_track: BTreeMap<CursorTrack, BTreeSet<Id>> = BTreeMap::new();
    for row in cursors.values() {
        by_track
            .entry(row.track.clone())
            .or_default()
            .insert(row.id);
    }
    let mut tracks = BTreeMap::new();
    for (track, members) in by_track {
        let replaced: BTreeSet<Id> = members
            .iter()
            .flat_map(|id| cursors[id].predecessors.iter().copied())
            .collect();
        let mut heads: Vec<CursorRow> = members
            .difference(&replaced)
            .map(|id| cursors[id].clone())
            .collect();
        heads.sort_by_key(|row| row.id);
        let resolution = match heads.as_slice() {
            [row] => CursorResolution::Unique(row.clone()),
            [] => bail!(
                "Comb cursor track ({}, {}) has no live head",
                track.stream,
                track.persona
            ),
            rows if rows.iter().all(|row| row.state == rows[0].state) => {
                CursorResolution::Agreed(heads)
            }
            _ => CursorResolution::Forked(heads),
        };
        tracks.insert(track, resolution);
    }
    Ok(CombCatalog { cursors, tracks })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(seconds: f64) -> IntervalValue {
        let at = hifitime::Epoch::from_tai_seconds(seconds);
        (at, at).try_to_inline().unwrap()
    }

    fn draft(position: Option<f64>, predecessors: impl IntoIterator<Item = Id>) -> CursorDraft {
        CursorDraft {
            stream: "memory-replay".to_owned(),
            persona: "agent-a".to_owned(),
            position: position.map(point),
            anchor: None,
            grain: position.map(|_| "2h".to_owned()),
            predecessors: predecessors.into_iter().collect(),
            observed_at: BTreeSet::from([point(100.0)]),
        }
    }

    fn facts(fragments: impl IntoIterator<Item = Fragment>) -> TribleSet {
        let mut facts = TribleSet::new();
        for fragment in fragments {
            facts += fragment;
        }
        facts
    }

    #[test]
    fn retry_identity_excludes_observation_time() {
        let first = cursor_fragment(draft(Some(10.0), [])).unwrap();
        let mut replay = draft(Some(10.0), []);
        replay.observed_at = BTreeSet::from([point(200.0)]);
        let replay = cursor_fragment(replay).unwrap();
        assert_eq!(first.1, replay.1);
        assert_ne!(first.0, replay.0);
    }

    #[test]
    fn concurrent_advances_are_visible_until_rejoined() {
        let (genesis_fragment, genesis) = cursor_fragment(draft(Some(0.0), [])).unwrap();
        let (left_fragment, left) = cursor_fragment(draft(Some(10.0), [genesis])).unwrap();
        let (right_fragment, right) = cursor_fragment(draft(Some(20.0), [genesis])).unwrap();
        let fork = load_catalog(&facts([
            genesis_fragment.clone(),
            left_fragment.clone(),
            right_fragment.clone(),
        ]))
        .unwrap();
        assert!(matches!(
            fork.resolution("memory-replay", "agent-a"),
            Some(CursorResolution::Forked(rows)) if rows.len() == 2
        ));

        let (join_fragment, join) = cursor_fragment(draft(Some(20.0), [left, right])).unwrap();
        let joined = load_catalog(&facts([
            genesis_fragment,
            left_fragment,
            right_fragment,
            join_fragment,
        ]))
        .unwrap();
        assert_eq!(
            joined
                .resolution("memory-replay", "agent-a")
                .unwrap()
                .head_ids(),
            vec![join]
        );
    }

    #[test]
    fn stopped_state_has_no_position_anchor_or_grain() {
        let stopped = cursor_fragment(draft(None, [])).unwrap();
        let catalog = load_catalog(&facts([stopped.0])).unwrap();
        let state = catalog
            .resolution("memory-replay", "agent-a")
            .unwrap()
            .settled_state()
            .unwrap();
        assert_eq!(state.position, None);
        assert_eq!(state.anchor, None);
        assert_eq!(state.grain, None);
    }

    #[test]
    fn exact_anchor_participates_in_cursor_identity() {
        let (_, anchor) = cursor_fragment(draft(Some(1.0), [])).unwrap();
        let plain = cursor_fragment(draft(Some(2.0), [])).unwrap();
        let mut anchored = draft(Some(2.0), []);
        anchored.anchor = Some(anchor);
        let anchored = cursor_fragment(anchored).unwrap();
        assert_ne!(plain.1, anchored.1);

        let catalog = load_catalog(&facts([anchored.0])).unwrap();
        assert_eq!(
            catalog
                .resolution("memory-replay", "agent-a")
                .unwrap()
                .settled_state()
                .unwrap()
                .anchor,
            Some(anchor)
        );

        let mut stopped = draft(None, []);
        stopped.anchor = Some(anchor);
        assert!(cursor_fragment(stopped)
            .unwrap_err()
            .to_string()
            .contains("cannot retain a grain or anchor"));
    }

    #[test]
    fn cross_track_predecessor_is_rejected() {
        let (first_fragment, first) = cursor_fragment(draft(Some(1.0), [])).unwrap();
        let mut other = draft(Some(2.0), [first]);
        other.persona = "agent-b".to_owned();
        let other = cursor_fragment(other).unwrap().0;
        assert!(load_catalog(&facts([first_fragment, other]))
            .unwrap_err()
            .to_string()
            .contains("supersedes cursor"));
    }

    #[test]
    fn redundant_predecessor_is_rejected() {
        let (a_fragment, a) = cursor_fragment(draft(Some(1.0), [])).unwrap();
        let (b_fragment, b) = cursor_fragment(draft(Some(2.0), [a])).unwrap();
        let c_fragment = cursor_fragment(draft(Some(3.0), [a, b])).unwrap().0;
        assert!(load_catalog(&facts([a_fragment, b_fragment, c_fragment]))
            .unwrap_err()
            .to_string()
            .contains("non-antichain"));
    }
}
