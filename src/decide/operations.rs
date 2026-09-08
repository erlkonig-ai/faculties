//! Configured operations over one frozen authorized Decide observation.
use std::path::{Path, PathBuf};

use crate::clock;
use crate::collection_names::open_configured;
use crate::decide::{
    self, DecisionGenesis, FactorRecord, FactorSide, IntervalValue, Resolution, ResolutionSnapshot,
};
use crate::schemas::decide::DEFAULT_SCOPE_ID;
use crate::storage::{load_signer, open_pile_strict, FactArchive};
use anyhow::{anyhow, bail, Context, Result};
use hifitime::Epoch;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::{Collection, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::SnapshotSource;
use triblespace::prelude::*;

#[derive(Clone, Debug)]
pub struct Decide {
    pile: PathBuf,
    key: Option<PathBuf>,
}
#[derive(Clone, Copy, Debug)]
pub struct ProposedDecision {
    pub decision: Id,
    pub genesis: Id,
}
#[derive(Clone, Copy, Debug)]
pub struct AddedFactor {
    pub decision: Id,
    pub factor: Id,
    pub side: FactorSide,
}
#[derive(Clone, Debug)]
pub struct ResolutionReceipt {
    pub decision: Id,
    pub head: Id,
    pub result: Option<Id>,
    pub forced: bool,
    pub evidence: Vec<Id>,
    pub predecessors: Vec<Id>,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct ListOptions {
    pub all: bool,
    pub forced: bool,
}
#[derive(Clone, Debug)]
pub struct DecisionSummary {
    pub id: Id,
    pub genesis: DecisionGenesis,
    pub title: String,
    pub pros: usize,
    pub cons: usize,
    pub resolution: Resolution,
    /// Present only for a semantically resolved state. No outcome is selected
    /// from divergent or invalid heads.
    pub outcome: Option<String>,
}
#[derive(Clone, Debug)]
pub struct FactorDetail {
    pub record: FactorRecord,
    pub text: String,
}
#[derive(Clone, Debug)]
pub struct ResolutionText {
    pub head: Id,
    pub outcome: String,
}
#[derive(Clone, Debug)]
pub struct DecisionDetail {
    pub id: Id,
    pub genesis: DecisionGenesis,
    pub title: String,
    pub context: Option<String>,
    pub factors: Vec<FactorDetail>,
    pub resolution: Resolution,
    pub outcomes: Vec<ResolutionText>,
}

/// Pure domain validation; no @file/stdin expansion.
pub fn validate_prose(text: &str, field: &str) -> Result<()> {
    super::canonical_required(text, field).map(|_| ())
}
pub fn result_id(raw: &str) -> Result<Id> {
    let raw = raw.trim();
    decide::result_tag(raw)
        .or_else(|| Id::from_hex(raw))
        .ok_or_else(|| {
            anyhow!(
                "unknown result '{raw}'; expected a 32-character id or one of: {}",
                decide::RESULT_TAGS
                    .iter()
                    .map(|(label, _)| *label)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

impl Decide {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self { pile, key }
    }
    fn storage(&self) -> DecideStorage<'_> {
        DecideStorage {
            pile: &self.pile,
            key: self.key.as_deref(),
        }
    }
    pub fn propose(
        &self,
        title: &str,
        context: Option<&str>,
        about: Option<Id>,
    ) -> Result<ProposedDecision> {
        validate_prose(title, "decision title")?;
        if let Some(context) = context {
            validate_prose(context, "decision context")?;
        }
        let decision = genid().id;
        self.storage().update("propose Decide decision", |_| {
            let (fragment, genesis) = decide::decision_fragment(
                decision,
                title,
                context.map(str::to_owned),
                about,
                epoch_interval(now_epoch()?),
            )?;
            Ok((fragment, ProposedDecision { decision, genesis }))
        })
    }
    pub fn factor(&self, input: &str, text: &str, side: FactorSide) -> Result<AddedFactor> {
        validate_prose(text, "factor text")?;
        let description = match side {
            FactorSide::Pro => "add Decide pro factor",
            FactorSide::Con => "add Decide con factor",
        };
        self.storage().update(description, |view| {
            let decision = resolve_decision(input, &view.facts)?;
            ensure_missing(
                &decide::resolution(&view.facts, decision),
                "add a factor",
                decision,
            )?;
            let (fragment, factor) = decide::factor_fragment(
                genid().id,
                decision,
                side,
                text,
                epoch_interval(now_epoch()?),
            )?;
            Ok((
                fragment,
                AddedFactor {
                    decision,
                    factor,
                    side,
                },
            ))
        })
    }
    pub fn resolve(
        &self,
        decision: &str,
        outcome: &str,
        result: Option<Id>,
        forced: bool,
    ) -> Result<ResolutionReceipt> {
        self.finish_resolution(decision, outcome, result, forced, false)
    }
    pub fn reconcile(
        &self,
        decision: &str,
        outcome: &str,
        result: Option<Id>,
        forced: bool,
    ) -> Result<ResolutionReceipt> {
        self.finish_resolution(decision, outcome, result, forced, true)
    }
    fn finish_resolution(
        &self,
        input: &str,
        outcome: &str,
        result: Option<Id>,
        forced: bool,
        reconcile: bool,
    ) -> Result<ResolutionReceipt> {
        validate_prose(outcome, "resolution outcome")?;
        let description = if reconcile {
            "reconcile Decide resolution fork"
        } else {
            "resolve Decide decision"
        };
        self.storage().update(description, |view| {
            let decision = resolve_decision(input, &view.facts)?;
            let state = decide::resolution(&view.facts, decision);
            let predecessors = if reconcile {
                reconciliation_heads(state, decision)?
            } else {
                ensure_missing(&state, "resolve it again", decision)?;
                Vec::new()
            };
            let mut evidence = evidence(&view.facts, decision, forced)?;
            evidence.sort_unstable();
            let (fragment, head) = decide::resolution_fragment(
                decision,
                outcome,
                result,
                forced,
                &evidence,
                &predecessors,
                epoch_interval(now_epoch()?),
            )?;
            Ok((
                fragment,
                ResolutionReceipt {
                    decision,
                    head,
                    result,
                    forced,
                    evidence,
                    predecessors,
                },
            ))
        })
    }
    pub fn list(&self, options: ListOptions) -> Result<Vec<DecisionSummary>> {
        self.storage().with_view(|view| {
            collect_decisions(view)?
                .into_iter()
                .filter(|row| {
                    if options.forced {
                        common_snapshot(&row.resolution).is_some_and(|snapshot| snapshot.forced)
                    } else if options.all {
                        true
                    } else {
                        matches!(
                            row.resolution,
                            Resolution::Missing | Resolution::Forked(_) | Resolution::Invalid(_)
                        )
                    }
                })
                .map(|row| {
                    let title = decide::read_text(&view.reader, row.genesis.title)?;
                    let outcome = common_snapshot(&row.resolution)
                        .map(|snapshot| decide::read_text(&view.reader, snapshot.outcome))
                        .transpose()?;
                    Ok(DecisionSummary {
                        id: row.id,
                        genesis: row.genesis,
                        title,
                        pros: row.pros,
                        cons: row.cons,
                        resolution: row.resolution,
                        outcome,
                    })
                })
                .collect()
        })
    }
    pub fn show(&self, input: &str) -> Result<DecisionDetail> {
        self.storage().with_view(|view| {
            let id = resolve_decision(input, &view.facts)?;
            let genesis = decide::genesis_for_decision(&view.facts, id)?
                .ok_or_else(|| anyhow!("decision {id:x} has no genesis"))?;
            let title = decide::read_text(&view.reader, genesis.title)?;
            let context = genesis
                .context
                .map(|handle| decide::read_text(&view.reader, handle))
                .transpose()?;
            let factors = decide::factors_for_decision(&view.facts, id)?
                .into_iter()
                .map(|record| {
                    Ok(FactorDetail {
                        text: decide::read_text(&view.reader, record.text)?,
                        record,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let resolution = decide::resolution(&view.facts, id);
            let snapshots: &[ResolutionSnapshot] = match &resolution {
                Resolution::Unique(snapshot) => std::slice::from_ref(snapshot),
                Resolution::Agreed(snapshots) | Resolution::Forked(snapshots) => snapshots,
                Resolution::Missing | Resolution::Invalid(_) => &[],
            };
            let outcomes = snapshots
                .iter()
                .map(|snapshot| {
                    Ok(ResolutionText {
                        head: snapshot.id,
                        outcome: decide::read_text(&view.reader, snapshot.outcome)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(DecisionDetail {
                id,
                genesis,
                title,
                context,
                factors,
                resolution,
                outcomes,
            })
        })
    }
    pub fn resolve_id(&self, prefix: &str) -> Result<Id> {
        self.storage()
            .with_view(|view| resolve_decision(prefix, &view.facts))
    }
}

#[derive(Clone, Copy)]
struct DecideStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

struct CollectionView {
    facts: FactArchive,
    reader: PileSnapshot,
}

impl DecideStorage<'_> {
    fn with_store<T>(
        &self,
        operation: impl FnOnce(
            &mut Pile,
            Collection<SimpleArchive>,
            &ed25519_dalek::SigningKey,
            &CollectionView,
        ) -> Result<T>,
    ) -> Result<T> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = (|| {
            let collection = open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
            let descriptor_snapshot = pile.snapshot()?;
            let policy = collection.policy(&descriptor_snapshot)?;
            drop(descriptor_snapshot);
            let maintained_succinct =
                pile.derive::<SuccinctArchiveBlob>(collection, (), policy.clone())?;
            let maintained_rank9 = pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(
                maintained_succinct,
                (),
                policy,
            )?;
            let store_snapshot = pollster::block_on(async {
                drop(pile.ensure(collection).await?);
                drop(pile.maintain(maintained_succinct).await?);
                pile.maintain(maintained_rank9).await
            })
            .context("maintain Decide fact collection")?;
            let facts = store_snapshot
                .collection(maintained_rank9)
                .context("observe maintained Decide fact collection")?
                .view::<FactArchive>()
                .context("read maintained Decide fact collection")?;
            operation(
                &mut pile,
                collection,
                &signer,
                &CollectionView {
                    facts,
                    reader: store_snapshot,
                },
            )
        })();
        finish_pile(pile, result)
    }

    fn with_view<T>(&self, operation: impl FnOnce(&CollectionView) -> Result<T>) -> Result<T> {
        self.with_store(|_, _, _, view| operation(view))
    }

    fn update<T>(
        &self,
        description: &'static str,
        operation: impl FnOnce(&CollectionView) -> Result<(Fragment, T)>,
    ) -> Result<T> {
        self.with_store(|pile, collection, signer, view| {
            let (mut fragment, value) = operation(view)?;
            fragment.describe_with(entity! { metadata::description: description });
            pile.commit(collection, signer, fragment)
                .context("commit authored Decide fragment")?;
            Ok(value)
        })
    }
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close Decide pile")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Decide pile also failed: {close_error}")))
        }
    }
}

fn now_epoch() -> Result<Epoch> {
    clock::now()
}

fn epoch_interval(epoch: Epoch) -> IntervalValue {
    (epoch, epoch)
        .try_to_inline()
        .expect("valid point interval")
}

fn interval_key(interval: IntervalValue) -> i128 {
    let (lower, _): (i128, i128) = interval
        .try_from_inline()
        .expect("validated point interval");
    lower
}

fn resolve_decision(input: &str, facts: &FactArchive) -> Result<Id> {
    crate::resolve_id_prefix(input, decide::decision_anchors(facts))
}

fn ensure_missing(state: &Resolution, action: &str, decision: Id) -> Result<()> {
    match state {
        Resolution::Missing => Ok(()),
        Resolution::Unique(snapshot) => {
            bail!(
                "decision {decision:x} is already resolved at head {:x}; cannot {action}",
                snapshot.id
            )
        }
        Resolution::Agreed(snapshots) => bail!(
            "decision {decision:x} is already resolved by {} agreeing heads; cannot {action}",
            snapshots.len()
        ),
        Resolution::Forked(snapshots) => bail!(
            "decision {decision:x} has {} divergent resolution heads; use `decide reconcile`",
            snapshots.len()
        ),
        Resolution::Invalid(reason) => {
            bail!("decision {decision:x} resolution is invalid: {reason}")
        }
    }
}

fn reconciliation_heads(state: Resolution, decision: Id) -> Result<Vec<Id>> {
    match state {
        Resolution::Forked(snapshots) => {
            Ok(snapshots.into_iter().map(|snapshot| snapshot.id).collect())
        }
        Resolution::Missing => bail!("decision {decision:x} is unresolved; use `decide resolve`"),
        Resolution::Unique(snapshot) => bail!(
            "decision {decision:x} has one closed resolution head {:x}; there is no fork to reconcile",
            snapshot.id
        ),
        Resolution::Agreed(snapshots) => bail!(
            "decision {decision:x} is already semantically resolved by {} agreeing heads",
            snapshots.len()
        ),
        Resolution::Invalid(reason) => bail!("decision {decision:x} resolution is invalid: {reason}"),
    }
}

fn evidence(facts: &FactArchive, decision: Id, forced: bool) -> Result<Vec<Id>> {
    let factors = decide::factors_for_decision(facts, decision)?;
    let pros = factors
        .iter()
        .filter(|factor| factor.side == FactorSide::Pro)
        .count();
    let cons = factors
        .iter()
        .filter(|factor| factor.side == FactorSide::Con)
        .count();
    if !forced && (pros == 0 || cons == 0) {
        bail!(
            "cannot resolve without force: exact evidence needs at least one pro and one con (have {pros} pro, {cons} con)"
        );
    }
    Ok(factors.into_iter().map(|factor| factor.id).collect())
}

#[derive(Clone, Debug)]
struct DecisionRow {
    id: Id,
    genesis: DecisionGenesis,
    pros: usize,
    cons: usize,
    resolution: Resolution,
}

fn collect_decisions(view: &CollectionView) -> Result<Vec<DecisionRow>> {
    let mut rows = Vec::new();
    for id in decide::decision_anchors(&view.facts) {
        let genesis = decide::genesis_for_decision(&view.facts, id)?
            .ok_or_else(|| anyhow!("decision {id:x} has no genesis"))?;
        let factors = decide::factors_for_decision(&view.facts, id)?;
        rows.push(DecisionRow {
            id,
            genesis,
            pros: factors
                .iter()
                .filter(|factor| factor.side == FactorSide::Pro)
                .count(),
            cons: factors
                .iter()
                .filter(|factor| factor.side == FactorSide::Con)
                .count(),
            resolution: decide::resolution(&view.facts, id),
        });
    }
    rows.sort_by_key(|row| std::cmp::Reverse((interval_key(row.genesis.created_at), row.id)));
    Ok(rows)
}

pub(super) fn common_snapshot(resolution: &Resolution) -> Option<&ResolutionSnapshot> {
    match resolution {
        Resolution::Unique(snapshot) => Some(snapshot),
        Resolution::Agreed(snapshots) => snapshots.first(),
        Resolution::Missing | Resolution::Forked(_) | Resolution::Invalid(_) => None,
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
