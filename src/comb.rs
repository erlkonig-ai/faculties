//! Canonical persona-scoped cursor DAG for Memory practices.
//!
//! A cursor snapshot is an immutable state on the `(stream, persona)` track.
//! Its direct `metadata::supersedes` antichain is part of intrinsic identity;
//! observation times are additive exhaust.  Concurrent advances therefore
//! remain visible as a fork, and a later snapshot can reconcile them by naming
//! every live head without any last-write-wins clock.

use std::collections::BTreeSet;

use anyhow::{anyhow, bail, Result};
use triblespace::core::metadata;
use triblespace::prelude::*;

use crate::schemas::memory::comb::{
    cursor_anchor, cursor_grain, cursor_persona, cursor_position, cursor_stream, kind_comb_cursor,
};

pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

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

/// Resolve one cursor track directly from any query substrate.
///
/// This is the ordinary open-world read path. It asks only for the typed
/// cursor facts needed by `stream`/`persona`: unknown rows remain inert,
/// scalar multiplicity remains visible as alternative projections, and no
/// whole-Comb catalog or intrinsic-id validation is performed.
pub fn resolution<P: TriblePattern>(
    facts: &P,
    stream: &str,
    persona: &str,
) -> Result<Option<CursorResolution>> {
    let members: BTreeSet<Id> = find!(
        id: Id,
        pattern!(facts, [{
            ?id @ metadata::tag: &kind_comb_cursor,
            cursor_stream: stream,
            cursor_persona: persona,
        }])
    )
    .collect();
    if members.is_empty() {
        return Ok(None);
    }

    let track = CursorTrack {
        stream: stream.to_owned(),
        persona: persona.to_owned(),
    };
    let mut rows = Vec::new();
    for id in members {
        let has_position = exists!(pattern!(facts, [{ id @ cursor_position: _?position }]));
        let positions: BTreeSet<IntervalValue> = find!(
            value: IntervalValue,
            pattern!(facts, [{ id @ cursor_position: ?value }])
        )
        .filter(|value| {
            value
                .try_from_inline()
                .is_ok_and(|(lower, upper): (i128, i128)| lower == upper)
        })
        .collect();
        let has_anchor = exists!(pattern!(facts, [{ id @ cursor_anchor: _?anchor }]));
        let anchors: BTreeSet<Id> =
            find!(value: Id, pattern!(facts, [{ id @ cursor_anchor: ?value }])).collect();
        let has_grain = exists!(pattern!(facts, [{ id @ cursor_grain: _?grain }]));
        let grains: BTreeSet<String> =
            find!(value: String, pattern!(facts, [{ id @ cursor_grain: ?value }])).collect();
        let predecessors: BTreeSet<Id> = find!(
            value: Id,
            pattern!(facts, [{ id @ metadata::supersedes: ?value }])
        )
        .collect();
        let observed_at: BTreeSet<IntervalValue> = find!(
            value: IntervalValue,
            pattern!(facts, [{ id @ metadata::created_at: ?value }])
        )
        .filter(|value| {
            value
                .try_from_inline()
                .is_ok_and(|(lower, upper): (i128, i128)| lower == upper)
        })
        .collect();

        if positions.is_empty() {
            if !has_position && !has_anchor && !has_grain {
                rows.push(CursorRow {
                    id,
                    track: track.clone(),
                    state: CursorState {
                        position: None,
                        anchor: None,
                        grain: None,
                    },
                    predecessors,
                    observed_at,
                });
            }
            continue;
        }
        if (has_anchor && anchors.is_empty()) || (has_grain && grains.is_empty()) {
            continue;
        }

        let anchors: Vec<Option<Id>> = if anchors.is_empty() {
            vec![None]
        } else {
            anchors.into_iter().map(Some).collect()
        };
        let grains: Vec<Option<String>> = if grains.is_empty() {
            vec![None]
        } else {
            grains.into_iter().map(Some).collect()
        };
        for position in positions {
            for anchor in &anchors {
                for grain in &grains {
                    rows.push(CursorRow {
                        id,
                        track: track.clone(),
                        state: CursorState {
                            position: Some(position),
                            anchor: *anchor,
                            grain: grain.clone(),
                        },
                        predecessors: predecessors.clone(),
                        observed_at: observed_at.clone(),
                    });
                }
            }
        }
    }

    if rows.is_empty() {
        return Ok(None);
    }
    let typed_members: BTreeSet<Id> = rows.iter().map(|row| row.id).collect();
    let replaced: BTreeSet<Id> = rows
        .iter()
        .flat_map(|row| row.predecessors.iter().copied())
        .filter(|predecessor| typed_members.contains(predecessor))
        .collect();
    let mut heads: Vec<_> = rows
        .into_iter()
        .filter(|row| !replaced.contains(&row.id))
        .collect();
    heads.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| {
                left.state
                    .position
                    .map(|value| value.raw)
                    .cmp(&right.state.position.map(|value| value.raw))
            })
            .then_with(|| left.state.anchor.cmp(&right.state.anchor))
            .then_with(|| left.state.grain.cmp(&right.state.grain))
    });
    let resolution = match heads.as_slice() {
        [] => bail!("Comb cursor track ({stream}, {persona}) has no typed live head"),
        [row] => CursorResolution::Unique(row.clone()),
        rows if rows.iter().all(|row| row.state == rows[0].state) => {
            CursorResolution::Agreed(heads)
        }
        _ => CursorResolution::Forked(heads),
    };
    Ok(Some(resolution))
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

fn point(field: &str, value: IntervalValue) -> Result<()> {
    let (lower, upper): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode {field}: {error:?}"))?;
    if lower != upper {
        bail!("{field} must be a point interval");
    }
    Ok(())
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

pub fn cursor_fragment(draft: CursorDraft) -> Result<(Fragment, Id)> {
    validate_short("cursor stream", &draft.stream)?;
    validate_short("cursor persona", &draft.persona)?;
    if let Some(position) = draft.position {
        point("cursor position", position)?;
    } else if draft.grain.is_some() || draft.anchor.is_some() {
        bail!("a stopped cursor cannot retain a grain or anchor");
    }
    if let Some(grain) = &draft.grain {
        validate_short("cursor grain", grain)?;
    }
    for at in &draft.observed_at {
        point("cursor observation time", *at)?;
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
        let fork = facts([
            genesis_fragment.clone(),
            left_fragment.clone(),
            right_fragment.clone(),
        ]);
        assert!(matches!(
            resolution(&fork, "memory-replay", "agent-a").unwrap(),
            Some(CursorResolution::Forked(rows)) if rows.len() == 2
        ));

        let (join_fragment, join) = cursor_fragment(draft(Some(20.0), [left, right])).unwrap();
        let joined = facts([
            genesis_fragment,
            left_fragment,
            right_fragment,
            join_fragment,
        ]);
        assert_eq!(
            resolution(&joined, "memory-replay", "agent-a")
                .unwrap()
                .unwrap()
                .head_ids(),
            vec![join]
        );
    }

    #[test]
    fn stopped_state_has_no_position_anchor_or_grain() {
        let stopped = cursor_fragment(draft(None, [])).unwrap();
        let facts = facts([stopped.0]);
        let current = resolution(&facts, "memory-replay", "agent-a")
            .unwrap()
            .unwrap();
        let state = current.settled_state().unwrap();
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

        let facts = facts([anchored.0]);
        assert_eq!(
            resolution(&facts, "memory-replay", "agent-a")
                .unwrap()
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
    fn cross_track_predecessor_does_not_retract_this_track() {
        let (first_fragment, first) = cursor_fragment(draft(Some(1.0), [])).unwrap();
        let mut other = draft(Some(2.0), [first]);
        other.persona = "agent-b".to_owned();
        let other = cursor_fragment(other).unwrap();
        let facts = facts([first_fragment, other.0]);
        assert_eq!(
            resolution(&facts, "memory-replay", "agent-a")
                .unwrap()
                .unwrap()
                .head_ids(),
            vec![first]
        );
        assert_eq!(
            resolution(&facts, "memory-replay", "agent-b")
                .unwrap()
                .unwrap()
                .head_ids(),
            vec![other.1]
        );
    }

    #[test]
    fn redundant_predecessors_do_not_require_a_global_dag_validation() {
        let (a_fragment, a) = cursor_fragment(draft(Some(1.0), [])).unwrap();
        let (b_fragment, b) = cursor_fragment(draft(Some(2.0), [a])).unwrap();
        let c = cursor_fragment(draft(Some(3.0), [a, b])).unwrap();
        let facts = facts([a_fragment, b_fragment, c.0]);
        assert_eq!(
            resolution(&facts, "memory-replay", "agent-a")
                .unwrap()
                .unwrap()
                .head_ids(),
            vec![c.1]
        );
    }

    #[test]
    fn ordinary_resolution_accepts_opaque_ids_and_unrelated_facts() {
        let id = Id::new([0xA5; 16]).unwrap();
        let position = point(7.0);
        let fragment = entity! {
            ExclusiveId::force_ref(&id) @
                metadata::tag: &kind_comb_cursor,
                cursor_stream: "memory-replay",
                cursor_persona: "agent-a",
                cursor_position: &position,
                cursor_grain: "2h",
                metadata::description: "open world",
        };
        let facts = facts([fragment]);

        let current = resolution(&facts, "memory-replay", "agent-a")
            .unwrap()
            .unwrap();
        assert_eq!(current.head_ids(), vec![id]);
        assert_eq!(current.settled_state().unwrap().position, Some(position));
    }
}
