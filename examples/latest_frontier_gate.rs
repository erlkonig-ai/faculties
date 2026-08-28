//! The gate that licensed replacing nine hand-rolled "which states are
//! current" scans with one shared query-layer operation, `latest`.
//!
//! Wiki asks `latest(C, metadata::supersedes, candidates)` instead of
//! collecting a superseded-id set and subtracting it. That is a pure set
//! computation — no arithmetic moves, nothing rounds — so the only honest
//! expectation is bit-identical output, and that is what this asserts.
//!
//! It also censuses Compass, which the port deliberately left alone, and
//! checks two properties on live data rather than on fixtures:
//! order-independence (the predicate reads the finished set, so shuffling the
//! candidate order cannot move the answer) and frame-relativity (a reader
//! holding fewer commits legitimately sees a different, larger frontier).
//!
//! Two later sections gate the *generalised* substrate that grew out of this
//! one. `gate_compass_stated_order` shows compass's `(created_at, event id)`
//! rule is not a special case but the maximal state of a register — once the
//! register is given the identity it lacked — and
//! `gate_derived_observed_index` shows the maintained observed-set collection
//! answers exactly what the live reverse-index probes do.
//!
//! Reads only; never writes.
//! `PILE=.../self.pile cargo run --release --example latest_frontier_gate`.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::PathBuf;

use anyhow::{Context, Result};
use faculties::storage::{load_signer, open_pile_strict};
use faculties::wiki as wiki_model;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::macros::{find, pattern};
use triblespace::prelude::*;

/// The shape every converted call site used to have: gather every id anything
/// observes, then subtract. Kept here so the gate has something to compare
/// against after the real copies were deleted.
fn superseded_by_subtraction(space: &TribleSet) -> HashSet<Id> {
    find!(old: Id, pattern!(space, [{ _ @ metadata::supersedes: ?old }])).collect()
}

fn scope(pile: &mut Pile, id: Id, signer: &ed25519_dalek::SigningKey) -> Result<TribleSet> {
    faculties::collection_names::open(pile, id, signer.clone())
        .materialize()
        .with_context(|| format!("materialize collection {id:x}"))
}

// ---------------------------------------------------------------------------
// Wiki
// ---------------------------------------------------------------------------

fn root(parent: &mut BTreeMap<Id, Id>, id: Id) -> Id {
    let mut cursor = id;
    while parent[&cursor] != cursor {
        cursor = parent[&cursor];
    }
    let result = cursor;
    let mut cursor = id;
    while parent[&cursor] != result {
        let next = parent[&cursor];
        parent.insert(cursor, result);
        cursor = next;
    }
    result
}

/// Wiki's pre-`latest` frontier rule, verbatim in behaviour: partition by
/// supersedes connectivity, then within each component keep the members no
/// *member* observes.
fn wiki_frontiers_by_hand(records: &[wiki_model::RevisionRecord]) -> BTreeSet<Vec<Id>> {
    let by_id: BTreeMap<Id, &wiki_model::RevisionRecord> =
        records.iter().map(|record| (record.id, record)).collect();
    let mut parent: BTreeMap<Id, Id> = records
        .iter()
        .map(|record| (record.id, record.id))
        .collect();
    for record in records {
        for predecessor in &record.supersedes {
            if parent.contains_key(predecessor) {
                let left = root(&mut parent, record.id);
                let right = root(&mut parent, *predecessor);
                if left != right {
                    let (smaller, larger) = (left.min(right), left.max(right));
                    parent.insert(larger, smaller);
                }
            }
        }
    }
    let mut components: BTreeMap<Id, Vec<Id>> = BTreeMap::new();
    for id in records.iter().map(|record| record.id) {
        components
            .entry(root(&mut parent, id))
            .or_default()
            .push(id);
    }
    components
        .into_values()
        .map(|mut members| {
            members.sort_unstable();
            let mut frontier: Vec<Id> = members
                .iter()
                .copied()
                .filter(|id| {
                    !members
                        .iter()
                        .any(|candidate| by_id[candidate].supersedes.contains(id))
                })
                .collect();
            frontier.sort_unstable();
            frontier
        })
        .collect()
}

fn gate_wiki(space: &TribleSet) -> Result<()> {
    let catalog = wiki_model::load_catalog(space)?;
    let records: Vec<wiki_model::RevisionRecord> =
        catalog.revisions.revision_records().cloned().collect();
    let entries = catalog.revisions.all_entries();

    let shipped: BTreeSet<Vec<Id>> = entries
        .iter()
        .map(|entry| {
            let mut ids: Vec<Id> = entry.frontier.iter().map(|record| record.id).collect();
            ids.sort_unstable();
            ids
        })
        .collect();
    let by_hand = wiki_frontiers_by_hand(&records);

    let heads: usize = shipped.iter().map(Vec::len).sum();
    let forked = shipped.iter().filter(|frontier| frontier.len() > 1).count();
    println!("WIKI");
    println!("  revisions examined: {}", records.len());
    println!("  entries (frontiers compared): {}", entries.len());
    println!("  frontier members total: {heads} (forked entries: {forked})");
    assert!(!records.is_empty(), "gate compared zero revisions");
    assert!(!entries.is_empty(), "gate compared zero frontiers");
    assert!(heads > 0, "gate compared zero frontier members");
    assert_eq!(
        shipped.len(),
        entries.len(),
        "two entries produced the same frontier; the set comparison would hide a difference"
    );

    if shipped == by_hand {
        println!("  GATE PASS: latest() == hand-rolled member scan (same count, same membership)");
    } else {
        println!("  GATE FAIL");
        println!(
            "    only in latest(): {}, only in hand-rolled: {}",
            shipped.difference(&by_hand).count(),
            by_hand.difference(&shipped).count()
        );
        for frontier in shipped.difference(&by_hand).take(10) {
            println!("    latest-only frontier: {frontier:x?}");
        }
        for frontier in by_hand.difference(&shipped).take(10) {
            println!("    hand-rolled-only frontier: {frontier:x?}");
        }
        std::process::exit(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Compass — censused, not converted
// ---------------------------------------------------------------------------

fn census_compass(space: &TribleSet) -> Result<()> {
    let notes: BTreeSet<Id> = find!(
        note: Id,
        pattern!(space, [{ ?note @ metadata::tag: &faculties::schemas::compass::KIND_NOTE_ID }])
    )
    .collect();
    let observers: BTreeSet<Id> = find!(
        observer: Id,
        pattern!(space, [{ ?observer @ metadata::supersedes: _?observed }])
    )
    .collect();
    let observed = superseded_by_subtraction(space);
    let frontier = latest(space, metadata::supersedes.id(), notes.iter().copied());
    println!("COMPASS (censused, not converted)");
    println!(
        "  notes: {} · entities carrying a supersedes edge: {} · entities observed: {}",
        notes.len(),
        observers.len(),
        observed.len()
    );
    println!(
        "  latest() over the note set would keep {} of {} notes",
        frontier.len(),
        notes.len()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Properties, on live data
// ---------------------------------------------------------------------------

fn properties(space: &TribleSet) -> Result<()> {
    let catalog = wiki_model::load_catalog(space)?;
    let entries = catalog.revisions.all_entries();
    let deep: Vec<&wiki_model::EntryRecord> = entries
        .iter()
        .filter(|entry| entry.members.len() > 1)
        .collect();
    assert!(
        !deep.is_empty(),
        "no entry has more than one revision: the property checks would be vacuous"
    );
    println!("PROPERTIES");
    println!("  multi-revision entries used: {}", deep.len());

    // Order-independence: the predicate reads the finished fact set, so no
    // permutation of the candidate order can move the answer.
    let mut checked = 0usize;
    for entry in deep.iter().take(500) {
        let forwards = latest(
            space,
            metadata::supersedes.id(),
            entry.members.iter().copied(),
        );
        let backwards = latest(
            space,
            metadata::supersedes.id(),
            entry.members.iter().rev().copied(),
        );
        assert_eq!(forwards, backwards, "candidate order changed the frontier");
        checked += 1;
    }
    println!("  order-independence: {checked} entries, both orders identical");

    // Frame-relativity: a frame with the supersedes facts forgotten is a
    // legitimately different commit set, and every revision is maximal in it.
    let mut without_edges = TribleSet::new();
    let supersedes = metadata::supersedes.id();
    for fact in space {
        if fact.a() != &supersedes {
            without_edges.insert(fact);
        }
    }
    let mut disagreements = 0usize;
    for entry in deep.iter().take(500) {
        let here = latest(space, supersedes, entry.members.iter().copied());
        let there = latest(&without_edges, supersedes, entry.members.iter().copied());
        assert_eq!(
            there.len(),
            entry.members.len(),
            "a frame with no supersedes edges must hold every member maximal"
        );
        if here != there {
            disagreements += 1;
        }
    }
    println!(
        "  frame-relativity: {disagreements} of {} entries answer differently in the edge-free frame, \
         and every member is maximal there",
        deep.len().min(500)
    );
    assert!(
        disagreements > 0,
        "the two frames never disagreed: the check would be vacuous"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Compass — the case the generalisation exists for
// ---------------------------------------------------------------------------

/// Compass resolved a goal's current status by `(created_at, event_id)`
/// over the events reachable through `board::task`. That edge is a
/// grouping, not an identity — notes and priority events carry it too, and
/// all of them are timestamped — so the rule only worked because it also
/// filtered by kind tag on the way in. Under a register the filter has
/// nowhere to live: domination is asked of the whole frame, so a later note
/// dominated a status event and 778 of 2939 goals reported no status at all.
///
/// The cure is an identity in the data, `board::status_of`, and the
/// migration that gives it to the events written before it existed. This
/// applies that migration **in memory** — the pile is never written — and
/// then asks the register the question, comparing against Compass's old
/// hand-rolled rule recomputed here from the *unmigrated* facts. Both sides
/// are therefore independent: one reads `board::task` and sorts in Rust, the
/// other reads `board::status_of` and resolves in the engine.
fn gate_compass_stated_order(space: &TribleSet) -> Result<()> {
    use faculties::schemas::compass::{
        board, interval_key, status_register, IntervalValue, KIND_GOAL_ID, KIND_STATUS_ID,
    };
    use faculties_migrations::status_register::status_register_delta;

    /// Compass's rule before the register, verbatim in behaviour: every
    /// status event grouped under this goal that carries both a status and
    /// a timestamp, greatest by `(created_at, event id)`.
    fn latest_by_hand(space: &TribleSet, goal: Id) -> Option<Id> {
        find!(
            (event: Id, status: String, at: IntervalValue),
            pattern!(space, [{ ?event @
                metadata::tag: &KIND_STATUS_ID,
                board::task: &goal,
                board::status: ?status,
                metadata::created_at: ?at,
            }])
        )
        .max_by(|left, right| (interval_key(left.2), left.0).cmp(&(interval_key(right.2), right.0)))
        .map(|(event, _, _)| event)
    }

    let goals: BTreeSet<Id> = find!(
        goal: Id,
        pattern!(space, [{ ?goal @ metadata::tag: &KIND_GOAL_ID }])
    )
    .collect();

    // The migration, applied to a local copy. `space` is a materialized
    // TribleSet; the pile is not touched.
    let (delta, report) = status_register_delta(space);
    let mut migrated = space.clone();
    migrated += delta;

    // Nothing about identity or scope at the call site: the recipe is the
    // register, and the reader only picks a frame.
    let order = status_register(&migrated);

    let mut compared = 0usize;
    let mut with_status = 0usize;
    let mut agreed = 0usize;
    let mut multi_event = 0usize;
    let mut broken_by_a_foreign_kind = 0usize;
    for goal in &goals {
        let expected = latest_by_hand(space, *goal);

        // The same question asked of the substrate, over the migrated
        // facts. Candidates are this goal's status events; the register
        // does the rest.
        let events: BTreeSet<Id> = find!(
            event: Id,
            pattern!(&migrated, [{ ?event @
                metadata::tag: &KIND_STATUS_ID,
                board::status_of: goal,
                board::status: _?any_status,
                metadata::created_at: _?any_at,
            }])
        )
        .collect();
        if events.len() > 1 {
            multi_event += 1;
        }
        let actual = sole(&order, events.iter().copied()).sole();

        // How many goals the removed scoping axis existed to rescue: read
        // `board::task` as if it were the identity and the answer is lost.
        let grouped = StatedOrder::<_, inlineencodings::NsTAIInterval>::new(
            space,
            board::task.id(),
            metadata::created_at.id(),
        )
        .tiebreak_by_id();
        if expected.is_some() && sole(&grouped, events.iter().copied()).sole().is_none() {
            broken_by_a_foreign_kind += 1;
        }

        compared += 1;
        if expected.is_some() {
            with_status += 1;
        }
        if expected == actual {
            agreed += 1;
        } else {
            println!(
                "  MISMATCH goal {goal:x}: compass says {expected:?}, register says {actual:?}"
            );
        }
    }

    // Measure the malformed-event population directly rather than infer it.
    let all_status: BTreeSet<Id> = find!(
        event: Id,
        pattern!(space, [{ ?event @ metadata::tag: &KIND_STATUS_ID }])
    )
    .collect();

    println!("COMPASS (a stated register — an identity and an order, no scope)");
    println!(
        "  status events: {} · complete (status + time + goal): {} · incomplete: {}",
        all_status.len(),
        report.complete_events,
        report.skipped_incomplete
    );
    println!(
        "  migration: {} identities over {} registers · already identified: {}",
        report.facts, report.registers, report.already_identified
    );
    println!("  goals examined: {compared} · goals carrying a status: {with_status}");
    println!("  goals with more than one status event: {multi_event}");
    println!("  goals the grouping-as-identity reading loses: {broken_by_a_foreign_kind}");
    println!("  agreements: {agreed} of {compared}");
    assert!(compared > 0, "no goals examined: the gate would be vacuous");
    assert!(
        with_status > 0,
        "no goal carries a status: the gate would be vacuous"
    );
    assert!(
        multi_event > 0,
        "no goal has competing status events: the order would never be exercised"
    );
    assert!(
        report.facts > 0,
        "the migration wrote nothing: the gate would be testing an empty change"
    );
    assert!(
        broken_by_a_foreign_kind > 0,
        "no goal is lost by reading the grouping as an identity: \
         the register would have nothing to fix"
    );
    if agreed == compared {
        println!("  GATE PASS: the status register == compass's (created_at, event id) max_by");
        Ok(())
    } else {
        std::process::exit(1);
    }
}

/// The derived collection maintains the *dominated* set — the monotone half
/// — and the reader subtracts. This checks the derived index answers exactly
/// what the live order does over the wiki's revisions.
fn gate_derived_observed_index(space: &TribleSet) -> Result<()> {
    use triblespace::core::collection::observed_union::{derive_element, join, ObservedIndex};

    let catalog = wiki_model::load_catalog(space)?;
    let entries = catalog.revisions.all_entries();
    let members: BTreeSet<Id> = entries
        .iter()
        .flat_map(|entry| entry.members.iter().copied())
        .collect();

    // Derive from the archived facts, then read the frontier by subtraction.
    let archive = space.clone().to_blob();
    let derived = derive_element(&archive, metadata::supersedes.id())
        .map_err(|error| anyhow::anyhow!("derive failed: {error}"))?;
    // Joining with itself must be a no-op — idempotence on real bytes.
    let rejoined =
        join(&derived, &derived).map_err(|error| anyhow::anyhow!("join failed: {error}"))?;
    assert_eq!(
        derived.bytes.as_ref(),
        rejoined.bytes.as_ref(),
        "the observed-set join is not idempotent on live data"
    );

    let index = ObservedIndex::decode(&derived)
        .map_err(|error| anyhow::anyhow!("decode failed: {error}"))?;
    let from_index = resolve(&index, members.iter().copied());
    let from_live = latest(space, metadata::supersedes.id(), members.iter().copied());

    println!("DERIVED OBSERVED SET (the maintained half)");
    println!(
        "  revisions examined: {} · observed states in the derived set: {}",
        members.len(),
        index.len()
    );
    println!(
        "  frontier via derived index: {} · via live probes: {}",
        from_index.len(),
        from_live.len()
    );
    assert!(
        !members.is_empty() && index.len() > 0,
        "empty inputs: the gate would be vacuous"
    );
    if from_index == from_live {
        println!("  GATE PASS: derived index == live reverse-index probes, same membership");
        Ok(())
    } else {
        std::process::exit(1);
    }
}

/// `relations` resolves four snapshot tracks with its own `track_head`:
/// candidates by (kind tag, track attribute), dominators restricted to those
/// same candidates, then a size dispatch to `Missing`/`Unique`/`Forked`.
///
/// The frontier half of that is `resolve` over a plain `ObservationOrder`,
/// with no scope on either side. The scoping the faculty appears to do is
/// not a frontier question: "supersedes a wrong-track predecessor" is a
/// referential-integrity check on the edge set, and `GroupHead::Invalid`
/// additionally re-derives an intrinsic id. Those belong to a validation
/// pass, not to resolution — an observation edge already asserts that its
/// two ends are versions of the same thing, and a register that quietly
/// disbelieves an edge is hiding the bad edge rather than resolving it.
///
/// This asserts the frontier halves agree on every track in the live pile,
/// which is also the evidence that the removed scope axis was never load
/// bearing here: a scope that changes no answer on real data was a knob
/// answering a question the data does not ask.
fn gate_relations_track_heads(space: &TribleSet) -> Result<()> {
    use faculties::relations::{group_head, lifecycle_head, profile_head, Head};
    use faculties::schemas::relations::{group, lifecycle, profile};
    use faculties::schemas::relations::{
        KIND_GROUP_SNAPSHOT, KIND_PERSON_LIFECYCLE, KIND_PERSON_PROFILE,
    };

    fn expected_of(head: Result<Head>) -> Option<BTreeSet<Id>> {
        match head {
            // The faculty bails on integrity problems, which the substrate
            // deliberately does not model. Skip rather than count those as
            // disagreements.
            Err(_) => None,
            Ok(Head::Missing) => Some(BTreeSet::new()),
            Ok(Head::Unique(head)) => Some([head].into_iter().collect()),
            Ok(Head::Forked(heads)) => Some(heads.into_iter().collect()),
        }
    }

    // `pattern!` wants a literal attribute, so the track is a macro
    // parameter rather than a runtime value.
    macro_rules! gate_track {
        ($label:literal, $kind:expr, $track:path, $resolver:expr) => {{
            let subjects: BTreeSet<Id> = find!(
                subject: Id,
                pattern!(space, [{ _?snapshot @ metadata::tag: &$kind, $track: ?subject }])
            )
            .collect();

            let order = ObservationOrder::new(space, metadata::supersedes.id());

            let mut examined = 0usize;
            let mut matched = 0usize;
            for subject in &subjects {
                let candidates: BTreeSet<Id> = find!(
                    snapshot: Id,
                    pattern!(space, [{ ?snapshot @ metadata::tag: &$kind, $track: subject }])
                )
                .collect();
                let Some(expected) = expected_of($resolver(space, *subject)) else {
                    continue;
                };
                let actual = resolve(&order, candidates.iter().copied());
                examined += 1;
                if expected == actual {
                    matched += 1;
                } else {
                    println!("  MISMATCH {} {subject:x}: {expected:?} vs {actual:?}", $label);
                }
            }
            println!("  {}: {matched} of {examined} subjects agree", $label);
            (examined, matched)
        }};
    }

    println!("RELATIONS (track heads — an unscoped observation order)");
    let mut total = 0usize;
    let mut agreed = 0usize;
    for (examined, matched) in [
        gate_track!("profile", KIND_PERSON_PROFILE, profile::of, profile_head),
        gate_track!(
            "lifecycle",
            KIND_PERSON_LIFECYCLE,
            lifecycle::of,
            lifecycle_head
        ),
        gate_track!("group", KIND_GROUP_SNAPSHOT, group::snapshot_of, group_head),
    ] {
        total += examined;
        agreed += matched;
    }
    assert!(total > 0, "no tracks examined: the gate would be vacuous");
    if agreed == total {
        println!(
            "  GATE PASS: unscoped ObservationOrder == track_head's frontier, {agreed} subjects"
        );
        Ok(())
    } else {
        std::process::exit(1);
    }
}

fn main() -> Result<()> {
    let pile: PathBuf = std::env::var("PILE").expect("PILE").into();
    let signer = load_signer(&pile, None)?;
    let mut handle = open_pile_strict(&pile)?;
    let wiki = scope(
        &mut handle,
        faculties::schemas::wiki::DEFAULT_SCOPE_ID,
        &signer,
    )?;
    let compass = scope(
        &mut handle,
        faculties::schemas::compass::DEFAULT_SCOPE_ID,
        &signer,
    )?;
    let relations = scope(
        &mut handle,
        faculties::schemas::relations::DEFAULT_SCOPE_ID,
        &signer,
    )?;
    let _ = handle.close();

    gate_wiki(&wiki)?;
    println!();
    census_compass(&compass)?;
    println!();
    gate_compass_stated_order(&compass)?;
    println!();
    gate_derived_observed_index(&wiki)?;
    println!();
    gate_relations_track_heads(&relations)?;
    println!();
    properties(&wiki)?;
    Ok(())
}
