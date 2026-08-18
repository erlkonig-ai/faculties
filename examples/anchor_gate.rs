//! The gate that licensed dropping the legacy anchor edge from entry grouping.
//!
//! `entry_records` used to unite revisions sharing an `attrs::fragment` anchor
//! on top of uniting them by `metadata::supersedes`. Removing the anchor edge
//! is only safe if it never carried connectivity of its own, so this measures
//! the claim instead of arguing it: it computes the partition BOTH ways over a
//! real pile and requires them to be identical — same count, same membership.
//!
//! Run against the live corpus 2026-08-18 (`PILE=.../self.pile`): 11231
//! revisions (11130 legacy, 101 native) across 3035 anchors partition into 3095
//! entries either way, membership identical. It also censuses the migration's
//! timestamp ties — chain edges whose direction was decided by version id
//! rather than by authorship — because those orderings are synthetic guesses.
//! That count was 24 edges across 11 anchor groups.
//!
//! Reads only; never writes. `cargo run --release --example anchor_gate`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Context, Result};
use faculties::collection_cutover::{load_signer, open_pile_strict};
use faculties::wiki as wiki_model;
use triblespace::core::collection::Collection;
use triblespace::prelude::*;

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

fn unite(parent: &mut BTreeMap<Id, Id>, left: Id, right: Id) {
    let left = root(parent, left);
    let right = root(parent, right);
    if left != right {
        let (smaller, larger) = (left.min(right), left.max(right));
        parent.insert(larger, smaller);
    }
}

fn partition(records: &[wiki_model::RevisionRecord], anchors: bool) -> BTreeSet<Vec<Id>> {
    let mut parent: BTreeMap<Id, Id> = records.iter().map(|r| (r.id, r.id)).collect();
    for record in records {
        for predecessor in &record.supersedes {
            if parent.contains_key(predecessor) {
                unite(&mut parent, record.id, *predecessor);
            }
        }
    }
    if anchors {
        let mut same_fragment: BTreeMap<Id, Vec<Id>> = BTreeMap::new();
        for record in records {
            if let Some(fragment) = record.legacy_fragment {
                same_fragment.entry(fragment).or_default().push(record.id);
            }
        }
        for members in same_fragment.values() {
            if let Some((&first, rest)) = members.split_first() {
                for member in rest {
                    unite(&mut parent, first, *member);
                }
            }
        }
    }
    let mut components: BTreeMap<Id, Vec<Id>> = BTreeMap::new();
    for id in records.iter().map(|r| r.id) {
        components
            .entry(root(&mut parent, id))
            .or_default()
            .push(id);
    }
    components
        .into_values()
        .map(|mut members| {
            members.sort_unstable();
            members
        })
        .collect()
}

fn main() -> Result<()> {
    let pile: PathBuf = std::env::var("PILE").expect("PILE").into();
    let signer = load_signer(&pile, None)?;
    let mut handle = open_pile_strict(&pile)?;
    let facts = Collection::new(&mut handle, faculties::schemas::wiki::DEFAULT_SCOPE_ID, signer)
        .materialize()
        .context("materialize Wiki collection")?;
    let _ = handle.close();
    let catalog = wiki_model::load_catalog(&facts)?;
    let records: Vec<wiki_model::RevisionRecord> =
        catalog.revisions.revision_records().cloned().collect();

    let legacy = records.iter().filter(|r| !r.is_native()).count();
    let anchors: BTreeSet<Id> = records.iter().filter_map(|r| r.legacy_fragment).collect();
    println!(
        "revisions examined: {} (legacy {}, native {}); distinct legacy anchors: {}",
        records.len(),
        legacy,
        records.len() - legacy,
        anchors.len()
    );
    assert!(!records.is_empty(), "gate compared zero revisions");
    assert!(!anchors.is_empty(), "gate saw zero anchors: vacuous");

    let with = partition(&records, true);
    let without = partition(&records, false);
    println!("entries WITH anchor edge:    {}", with.len());
    println!("entries WITHOUT anchor edge: {}", without.len());

    // Recompute the migration's tie census from the live corpus: within each
    // anchor group, versions were ordered by the GREATEST observed created_at
    // and tie-broken on id. Adjacent pairs sharing a stamp are chain edges
    // whose direction was decided by id, not by authorship.
    let mut by_fragment: BTreeMap<Id, Vec<(Option<[u8; 32]>, Id)>> = BTreeMap::new();
    for record in &records {
        if let Some(fragment) = record.legacy_fragment {
            by_fragment
                .entry(fragment)
                .or_default()
                .push((record.authored_at().map(|value| value.raw), record.id));
        }
    }
    let mut ties = 0usize;
    let mut tied_groups = 0usize;
    for versions in by_fragment.values_mut() {
        versions.sort();
        let before = ties;
        for pair in versions.windows(2) {
            if pair[0].0 == pair[1].0 {
                ties += 1;
            }
        }
        if ties > before {
            tied_groups += 1;
        }
    }
    println!(
        "synthetic chain orderings (timestamp ties broken by id): {ties} edges across {tied_groups} anchor groups"
    );

    if with == without {
        println!("GATE PASS: partitions identical (same count, same membership)");
        return Ok(());
    }

    println!("GATE FAIL");
    let only_with: Vec<_> = with.difference(&without).collect();
    let only_without: Vec<_> = without.difference(&with).collect();
    println!(
        "components only in WITH: {}, only in WITHOUT: {}",
        only_with.len(),
        only_without.len()
    );
    for component in only_with.iter().take(20) {
        let pieces: Vec<&Vec<Id>> = without
            .iter()
            .filter(|c| c.iter().any(|id| component.contains(id)))
            .collect();
        println!(
            "  WITH component of {} members (first {:x}) splits into {} pieces",
            component.len(),
            component[0],
            pieces.len()
        );
        for piece in &pieces {
            let fragments: BTreeSet<String> = piece
                .iter()
                .filter_map(|id| {
                    records
                        .iter()
                        .find(|r| r.id == *id)
                        .and_then(|r| r.legacy_fragment)
                })
                .map(|f| format!("{f:x}"))
                .collect();
            println!(
                "     piece: {} members, first {:x}, anchors {:?}",
                piece.len(),
                piece[0],
                fragments
            );
        }
    }
    std::process::exit(1);
}
