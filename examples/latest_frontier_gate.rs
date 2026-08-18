//! The gate that licensed replacing nine hand-rolled "which states are
//! current" scans with one shared query-layer operation, `latest`.
//!
//! Wiki and Memory now ask `latest(C, metadata::supersedes, candidates)`
//! instead of collecting a superseded-id set and subtracting it. That is a
//! pure set computation — no arithmetic moves, nothing rounds — so the only
//! honest expectation is bit-identical output, and that is what this asserts:
//! it recomputes each faculty's *old* algorithm here, in this file, and
//! requires the same set with the same membership over the real pile.
//!
//! It also censuses Compass, which the port deliberately left alone, and
//! checks two properties on live data rather than on fixtures:
//! order-independence (the predicate reads the finished set, so shuffling the
//! candidate order cannot move the answer) and frame-relativity (a reader
//! holding fewer commits legitimately sees a different, larger frontier).
//!
//! Reads only; never writes.
//! `PILE=.../self.pile cargo run --release --example latest_frontier_gate`.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::PathBuf;

use anyhow::{Context, Result};
use faculties::memory as memory_model;
use faculties::memory_cover;
use faculties::storage::{load_signer, open_pile_strict};
use faculties::wiki as wiki_model;
use triblespace::core::collection::Collection;
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
    Collection::new(pile, id, signer.clone())
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
    let mut parent: BTreeMap<Id, Id> = records.iter().map(|record| (record.id, record.id)).collect();
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
        components.entry(root(&mut parent, id)).or_default().push(id);
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
// Memory
// ---------------------------------------------------------------------------

fn gate_memory(space: &TribleSet) -> Result<()> {
    let catalog = memory_model::load_catalog(space)?;

    // The old `MemoryCatalog::head_ids`: union every row's predecessors, then
    // subtract from the node set.
    let node_ids = catalog.node_ids();
    let superseded: BTreeSet<Id> = catalog
        .chunks
        .values()
        .flat_map(|row| row.predecessors.iter().copied())
        .chain(
            catalog
                .retractions
                .values()
                .flat_map(|row| row.predecessors.iter().copied()),
        )
        .collect();
    let heads_by_hand: BTreeSet<Id> = node_ids.difference(&superseded).copied().collect();
    let heads_shipped: BTreeSet<Id> = catalog.head_ids().into_iter().collect();

    // The old `memory_cover::superseded_ids` filter over every chunk id.
    let all_chunks = memory_cover::all_chunk_ids(space);
    let superseded_in_space = superseded_by_subtraction(space);
    let live_by_hand: BTreeSet<Id> = all_chunks
        .iter()
        .copied()
        .filter(|id| !superseded_in_space.contains(id))
        .collect();
    let live_shipped = memory_cover::live_chunk_ids(space);

    println!("MEMORY");
    println!(
        "  nodes examined: {} (chunks {}, retractions {})",
        node_ids.len(),
        catalog.chunks.len(),
        catalog.retractions.len()
    );
    println!("  superseded nodes: {}", superseded.len());
    println!(
        "  frontier (catalog heads): {} · live chunks: {}",
        heads_shipped.len(),
        live_shipped.len()
    );
    assert!(!node_ids.is_empty(), "gate compared zero Memory nodes");
    assert!(
        !superseded.is_empty(),
        "no Memory node is superseded on this pile: the comparison would be vacuous"
    );
    assert!(!heads_shipped.is_empty(), "gate compared zero Memory heads");
    assert!(!all_chunks.is_empty(), "gate compared zero Memory chunks");

    let mut ok = true;
    if heads_shipped == heads_by_hand {
        println!("  GATE PASS: catalog heads identical to the predecessor-subtraction rule");
    } else {
        ok = false;
        println!(
            "  GATE FAIL (heads): only in latest(): {:?}, only in hand-rolled: {:?}",
            heads_shipped
                .difference(&heads_by_hand)
                .take(10)
                .collect::<Vec<_>>(),
            heads_by_hand
                .difference(&heads_shipped)
                .take(10)
                .collect::<Vec<_>>()
        );
    }
    if live_shipped == live_by_hand {
        println!("  GATE PASS: live chunks identical to the superseded-id subtraction");
    } else {
        ok = false;
        println!(
            "  GATE FAIL (live chunks): only in latest(): {:?}, only in hand-rolled: {:?}",
            live_shipped
                .difference(&live_by_hand)
                .take(10)
                .collect::<Vec<_>>(),
            live_by_hand
                .difference(&live_shipped)
                .take(10)
                .collect::<Vec<_>>()
        );
    }
    if !ok {
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
        let forwards = latest(space, metadata::supersedes.id(), entry.members.iter().copied());
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

fn main() -> Result<()> {
    let pile: PathBuf = std::env::var("PILE").expect("PILE").into();
    let signer = load_signer(&pile, None)?;
    let mut handle = open_pile_strict(&pile)?;
    let wiki = scope(
        &mut handle,
        faculties::schemas::wiki::DEFAULT_SCOPE_ID,
        &signer,
    )?;
    let memory = scope(
        &mut handle,
        faculties::schemas::memory::DEFAULT_SCOPE_ID,
        &signer,
    )?;
    let compass = scope(
        &mut handle,
        faculties::schemas::compass::DEFAULT_SCOPE_ID,
        &signer,
    )?;
    let _ = handle.close();

    gate_wiki(&wiki)?;
    println!();
    gate_memory(&memory)?;
    println!();
    census_compass(&compass)?;
    println!();
    properties(&wiki)?;
    Ok(())
}
