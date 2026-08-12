//! The ADDITIVE migration: lineage as data, nothing rewritten, nothing minted.
//!
//! The legacy model reifies every version as its own entity and presents a
//! page's history as a flat, timestamp-ordered list — that is literally what
//! `wiki history` prints. It has no `supersedes` attribute, so it never says
//! which version follows which; the order is *implied* by `created_at` and read
//! off at display time.
//!
//! This migration writes that implication down. For each fragment, its version
//! entities are ordered by `created_at` and chained with `metadata::supersedes`.
//! Every legacy fact stays exactly where it is, every legacy id keeps its value
//! (a version id derives from `(fragment, title, content)`, which none of this
//! touches), and every citation in every page keeps pointing at an entity that
//! still exists.
//!
//! What it deliberately does NOT do:
//!
//! * **Read commit ancestry.** Commits are one layer up — batching, sync,
//!   debugging. "These two commits are concurrent" is a fact about how bytes
//!   arrived, not about what the wiki means, and the target model holds commits
//!   as a set with no parent relationships at all. Reconstructing semantic
//!   lineage from them would read meaning into the plumbing, and would invent a
//!   fork structure the source never asserts.
//! * **Rewrite link targets.** Nothing is re-pointed, so no citation can depend
//!   on another revision migrating first. The ordering constraint that produced
//!   every unresolved-citation refusal simply has no reason to exist.
//! * **Mint new entities.** Identity for revisions authored AFTER the cutover is
//!   content-derived; legacy revisions keep the identity they were written with.
//!   The DAG spans both because supersession is an ordinary edge, not a
//!   component of the legacy id.
//!
//! The transform can refuse structurally incomplete legacy versions (missing
//! `created_at` or `fragment`), because ordering those would invent evidence.
//! Once those source invariants hold, a chain has no cycles, a rewrite that
//! does not happen cannot fail, and an id that is not minted cannot collide.

use std::collections::BTreeMap;

use triblespace::core::metadata;
use triblespace::macros::{entity, find, pattern};
use triblespace::prelude::*;

use crate::schemas::wiki::attrs;

/// One commit's worth of atomically added facts.
///
/// It carries NO parents and NO signer. Commits are a layer up — batching,
/// sync, debugging — and the target model holds them as a set with no
/// relationships, so a type that still threaded ancestry through would be
/// keeping a door open onto exactly the derivation this migration rejects.
#[derive(Clone)]
pub struct LegacyDelta {
    /// The commit's metadata subject. Retained so facts can be attributed to
    /// the unit they arrived in; never consulted for ordering.
    pub commit: Id,
    pub facts: TribleSet,
}

/// A version that cannot take its place in a chain.
///
/// This migration ORDERS BY `created_at`, which makes the timestamp
/// load-bearing rather than decorative — so a version without one cannot be
/// placed, and placing it anyway would be inventing the order we claim to be
/// reading. Same for a version belonging to no fragment: it is in no page's
/// history by definition.
///
/// Both are REFUSED rather than accommodated. The legacy write path emitted
/// both on every version, so accepting either omission would invent placement
/// evidence rather than preserve it.
#[derive(Debug, PartialEq, Eq)]
pub struct Malformed {
    /// Tagged versions carrying no `created_at`.
    pub undated: Vec<Id>,
    /// Tagged versions carrying no `fragment`.
    pub unfragmented: Vec<Id>,
}

/// Supersedes edges, plus the shape of what produced them.
#[derive(Debug)]
pub struct AdditivePlan {
    /// The whole output: one `supersedes` fact per non-genesis version.
    pub facts: TribleSet,
    /// Distinct version entities seen across every delta.
    pub versions: usize,
    /// Distinct fragments they belong to.
    pub fragments: usize,
    /// Edges emitted. `versions - fragments` when every fragment is a chain.
    pub edges: usize,
    /// Adjacent pairs sharing a timestamp, where the version id broke the tie.
    /// Reported because a tie is the one place ordering is decided by something
    /// other than the evidence.
    pub ties: usize,
    /// `(fragment, earlier, later)` for each tie, so they can be LOOKED AT
    /// rather than merely counted. A count tells you the risk is small; only
    /// the list tells you whether the order it picked is right.
    pub ties_at: Vec<(Id, Id, Id)>,
    /// Entities tagged as versions. The READ path selects on this tag plus
    /// `fragment`; the migration selects on `fragment`. Censused because the two
    /// populations differing is precisely how a migration comes out consistent
    /// with itself and wrong about the corpus.
    pub tagged: usize,
    /// The legacy latest-state observation used to position each distinct id.
    /// All observations remain facts; this map lets the cutover place each
    /// derived edge on an authored leaf carrying its actual support.
    selected_created_at: BTreeMap<Id, [u8; 32]>,
}

impl AdditivePlan {
    pub(crate) fn selected_created_at(
        &self,
        version: Id,
    ) -> Option<Inline<inlineencodings::NsTAIInterval>> {
        self.selected_created_at
            .get(&version)
            .copied()
            .map(Inline::new)
    }
}

/// Chain each fragment's versions by `created_at`, tie-broken on version id.
///
/// Refuses if any version cannot be placed. Ties are not a refusal: they are
/// resolved deterministically and reported with the exact affected ids.
pub fn plan_additive(deltas: &[LegacyDelta]) -> Result<AdditivePlan, Malformed> {
    let mut fragment_of: BTreeMap<Id, Id> = BTreeMap::new();
    let mut stamp_of: BTreeMap<Id, [u8; 32]> = BTreeMap::new();
    let mut tagged: std::collections::BTreeSet<Id> = std::collections::BTreeSet::new();

    for d in deltas {
        for (vid,) in find!(
            (vid: Id),
            pattern!(&d.facts, [{ ?vid @ metadata::tag: &crate::schemas::wiki::KIND_VERSION_ID }])
        ) {
            tagged.insert(vid);
        }
        for (vid, frag) in find!(
            (vid: Id, frag: Id),
            pattern!(&d.facts, [{ ?vid @ attrs::fragment: ?frag }])
        ) {
            fragment_of.entry(vid).or_insert(frag);
        }
        // A version can appear in several commits because the deterministic
        // legacy writer deliberately reasserted an existing content-derived
        // id with a fresh timestamp. Legacy latest-version selection used the
        // GREATEST such observation. Keeping that projection is what turns
        // A(1), B(2), A(3) into B <- A instead of incorrectly leaving B current.
        // Every timestamp fact itself remains untouched in the migrated union.
        for (vid, ts) in find!(
            (vid: Id, ts: Inline<inlineencodings::NsTAIInterval>),
            pattern!(&d.facts, [{ ?vid @ metadata::created_at: ?ts }])
        ) {
            let slot = stamp_of.entry(vid).or_insert(ts.raw);
            if ts.raw > *slot {
                *slot = ts.raw;
            }
        }
    }

    let undated: Vec<Id> = tagged
        .iter()
        .copied()
        .filter(|v| !stamp_of.contains_key(v))
        .collect();
    let unfragmented: Vec<Id> = tagged
        .iter()
        .copied()
        .filter(|v| !fragment_of.contains_key(v))
        .collect();
    if !undated.is_empty() || !unfragmented.is_empty() {
        return Err(Malformed {
            undated,
            unfragmented,
        });
    }

    let mut by_fragment: BTreeMap<Id, Vec<Id>> = BTreeMap::new();
    for (vid, frag) in &fragment_of {
        by_fragment.entry(*frag).or_default().push(*vid);
    }

    let mut facts = TribleSet::new();
    let (mut edges, mut ties) = (0usize, 0usize);
    let mut ties_at: Vec<(Id, Id, Id)> = Vec::new();
    for (frag, versions) in by_fragment.iter_mut() {
        versions.sort_by_key(|v| (stamp_of.get(v).copied(), *v));
        for pair in versions.windows(2) {
            if stamp_of.get(&pair[0]) == stamp_of.get(&pair[1]) {
                ties += 1;
                ties_at.push((*frag, pair[0], pair[1]));
            }
            facts += entity! { ExclusiveId::force_ref(&pair[1]) @
                metadata::supersedes: &pair[0],
            }
            .into_facts();
            edges += 1;
        }
    }

    Ok(AdditivePlan {
        facts,
        versions: fragment_of.len(),
        fragments: by_fragment.len(),
        edges,
        ties,
        ties_at,
        tagged: tagged.len(),
        selected_created_at: stamp_of,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hifitime::Epoch;
    use triblespace::core::id_hex;

    const FRAG: Id = id_hex!("F0000000000000000000000000000001");
    const C1: Id = id_hex!("C0000000000000000000000000000001");
    const C2: Id = id_hex!("C0000000000000000000000000000002");
    const A: Id = id_hex!("A0000000000000000000000000000001");
    const B: Id = id_hex!("A0000000000000000000000000000002");
    const C: Id = id_hex!("A0000000000000000000000000000003");

    fn at(s: f64) -> Inline<inlineencodings::NsTAIInterval> {
        let e = Epoch::from_tai_seconds(s);
        (e, e).try_to_inline().expect("interval")
    }

    fn version(commit: Id, vid: Id, frag: Id, secs: f64) -> LegacyDelta {
        let facts = entity! { ExclusiveId::force_ref(&vid) @
            metadata::tag: &crate::schemas::wiki::KIND_VERSION_ID,
            attrs::fragment: frag,
            metadata::created_at: at(secs),
        }
        .into_facts();
        LegacyDelta { commit, facts }
    }

    /// A version with the shape the migration REFUSES, built by omission so the
    /// test cannot drift away from the real thing.
    fn malformed(commit: Id, vid: Id, frag: Option<Id>, secs: Option<f64>) -> LegacyDelta {
        let mut facts = entity! { ExclusiveId::force_ref(&vid) @
            metadata::tag: &crate::schemas::wiki::KIND_VERSION_ID,
        }
        .into_facts();
        if let Some(frag) = frag {
            facts += entity! { ExclusiveId::force_ref(&vid) @ attrs::fragment: frag }.into_facts();
        }
        if let Some(secs) = secs {
            facts += entity! { ExclusiveId::force_ref(&vid) @ metadata::created_at: at(secs) }
                .into_facts();
        }
        LegacyDelta { commit, facts }
    }

    /// THE NEGATIVE CONTROL. Ordering by `created_at` makes it load-bearing, so
    /// a version without one is refused rather than placed somewhere plausible.
    /// The test keeps that a checked invariant instead of an implicit guess.
    #[test]
    fn a_version_without_created_at_is_refused() {
        let err = plan_additive(&[
            version(C1, A, FRAG, 1_000.0),
            malformed(C1, B, Some(FRAG), None),
        ])
        .expect_err("an unplaceable version must refuse");
        assert_eq!(
            err,
            Malformed {
                undated: vec![B],
                unfragmented: vec![]
            }
        );
    }

    /// And a version belonging to no fragment is in no page's history by
    /// definition, so it is named rather than silently skipped.
    #[test]
    fn a_version_without_a_fragment_is_refused() {
        let err = plan_additive(&[
            version(C1, A, FRAG, 1_000.0),
            malformed(C1, B, None, Some(2_000.0)),
        ])
        .expect_err("a version belonging to no page must refuse");
        assert_eq!(
            err,
            Malformed {
                undated: vec![],
                unfragmented: vec![B]
            }
        );
    }

    fn chain(plan: &AdditivePlan) -> Vec<(Id, Id)> {
        find!(
            (later: Id, earlier: Id),
            pattern!(&plan.facts, [{ ?later @ metadata::supersedes: ?earlier }])
        )
        .collect()
    }

    /// Lineage follows `created_at`, NOT the order deltas arrive in and NOT
    /// commit structure — the deltas here are parentless and presented newest
    /// first, which is exactly the squash's shape.
    #[test]
    fn versions_chain_in_authoring_order_not_arrival_order() {
        let deltas = vec![
            version(C1, C, FRAG, 3_000.0),
            version(C1, A, FRAG, 1_000.0),
            version(C2, B, FRAG, 2_000.0),
        ];
        let plan = plan_additive(&deltas).expect("well-formed fixture");
        let mut edges = chain(&plan);
        edges.sort();
        assert_eq!(edges, vec![(B, A), (C, B)], "A <- B <- C");
        assert_eq!(plan.edges, 2);
        assert_eq!(
            plan.versions - plan.fragments,
            plan.edges,
            "one chain, no gaps"
        );
        assert_eq!(plan.ties, 0);
    }

    /// A tie is decided by version id, so the same corpus presented in any order
    /// yields the SAME chain. Ordering that varied with input order would make
    /// the migration irreproducible.
    #[test]
    fn a_timestamp_tie_is_broken_deterministically() {
        let forward =
            plan_additive(&[version(C1, A, FRAG, 1_000.0), version(C1, B, FRAG, 1_000.0)])
                .expect("well-formed fixture");
        let reversed =
            plan_additive(&[version(C1, B, FRAG, 1_000.0), version(C1, A, FRAG, 1_000.0)])
                .expect("well-formed fixture");
        assert_eq!(chain(&forward), vec![(B, A)], "lower id sorts first");
        assert_eq!(
            chain(&forward),
            chain(&reversed),
            "input order is irrelevant"
        );
        assert_eq!(forward.ties, 1, "and the tie is reported, not hidden");
    }

    /// A version restated in a later commit is the SAME entity, authored once.
    /// A squash re-states everything, so counting restatements as new versions
    /// would inflate the chain with duplicates of itself.
    #[test]
    fn a_restated_version_does_not_become_a_second_link() {
        let deltas = vec![
            version(C1, A, FRAG, 1_000.0),
            version(C2, B, FRAG, 2_000.0),
            // the squash restates A, later, with its ORIGINAL timestamp
            version(C2, A, FRAG, 1_000.0),
        ];
        let plan = plan_additive(&deltas).expect("well-formed fixture");
        assert_eq!(plan.versions, 2);
        assert_eq!(chain(&plan), vec![(B, A)]);
    }

    /// The deterministic legacy writer used a fresh timestamp when a revert
    /// reasserted an old content-derived id. The distinct-state DAG cannot
    /// represent A twice without inventing occurrence ids, so its one A node
    /// must occupy A's latest observed position and remain the frontier.
    #[test]
    fn a_revert_uses_the_latest_observation_of_the_reasserted_state() {
        let plan = plan_additive(&[
            version(C1, A, FRAG, 1_000.0),
            version(C1, B, FRAG, 2_000.0),
            version(C2, A, FRAG, 3_000.0),
        ])
        .expect("well-formed revert fixture");

        assert_eq!(plan.versions, 2, "A remains one preserved legacy id");
        assert_eq!(
            chain(&plan),
            vec![(A, B)],
            "B <- A, so reverted A is current"
        );
    }
}
