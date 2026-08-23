//! Collection-native Decide values, validation, and fork-visible resolution.
//!
//! Decision ids are stable random anchors. One intrinsic immutable genesis
//! describes each anchor, factors are independent intrinsic occurrences, and
//! resolutions form an intrinsic predecessor DAG. Set union is therefore the
//! only merge operation: concurrent outcomes remain visible and no timestamp
//! or iteration order chooses a winner.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::macros::{entity, find, pattern};
use triblespace::prelude::*;

use crate::schemas::decide::{
    decide, factor, resolution, KIND_CON, KIND_DECISION, KIND_DECISION_GENESIS, KIND_PRO,
    KIND_RESOLUTION_SNAPSHOT,
};
pub use crate::schemas::decide::{result_name, result_tag, RESULT_BENIGN, RESULT_TAGS};

pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactorSide {
    Pro,
    Con,
}

impl FactorSide {
    pub const fn kind(self) -> Id {
        match self {
            Self::Pro => KIND_PRO,
            Self::Con => KIND_CON,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Pro => "pro",
            Self::Con => "con",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionGenesis {
    pub id: Id,
    pub decision: Id,
    pub title: TextHandle,
    pub context: Option<TextHandle>,
    pub about: Option<Id>,
    pub created_at: IntervalValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactorRecord {
    pub id: Id,
    pub occurrence: Id,
    pub decision: Id,
    pub side: FactorSide,
    pub text: TextHandle,
    pub created_at: IntervalValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionSnapshot {
    pub id: Id,
    pub decision: Id,
    pub outcome: TextHandle,
    /// Machine-readable result, when the resolver stated one. The outcome
    /// prose is for a reader; this is the only field a gate may act on.
    pub result: Option<Id>,
    pub forced: bool,
    pub evidence: Vec<Id>,
    pub predecessors: Vec<Id>,
    pub finished_at: IntervalValue,
}

/// Fork-visible state of one decision's resolution track.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Resolution {
    Missing,
    Unique(ResolutionSnapshot),
    /// Multiple live events have the same observable outcome bytes and forced
    /// bit. Time, evidence, and history remain distinct join obligations.
    Agreed(Vec<ResolutionSnapshot>),
    /// Live heads disagree on outcome bytes or the explicit forced bit.
    Forked(Vec<ResolutionSnapshot>),
    Invalid(String),
}

impl Resolution {
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

fn point_interval(value: IntervalValue, field: &str) -> Result<()> {
    let (lower, upper): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode {field}: {error:?}"))?;
    if lower != upper {
        bail!("{field} must be a point interval");
    }
    Ok(())
}

fn decision_anchor_record(decision_id: Id) -> Fragment {
    entity! { ExclusiveId::force_ref(&decision_id) @ metadata::tag: &KIND_DECISION }
}

fn genesis_record(
    decision_id: Id,
    title: TextHandle,
    context: Option<TextHandle>,
    about: Option<Id>,
    created_at: IntervalValue,
) -> Fragment {
    entity! {
        metadata::tag: &KIND_DECISION_GENESIS,
        decide::of: &decision_id,
        metadata::name: title,
        metadata::description?: context.as_ref(),
        decide::about?: about.as_ref(),
        metadata::created_at: created_at,
    }
}

fn factor_record_fragment(
    occurrence: Id,
    decision_id: Id,
    side: FactorSide,
    text: TextHandle,
    created_at: IntervalValue,
) -> Fragment {
    let kind = side.kind();
    entity! {
        metadata::tag: &kind,
        factor::occurrence: &occurrence,
        factor::about_decision: &decision_id,
        metadata::name: text,
        metadata::created_at: created_at,
    }
}

fn resolution_record_fragment(snapshot: &ResolutionSnapshot) -> Fragment {
    entity! {
        metadata::tag: &KIND_RESOLUTION_SNAPSHOT,
        resolution::of: &snapshot.decision,
        decide::outcome: snapshot.outcome,
        resolution::result?: snapshot.result.as_ref(),
        resolution::forced: snapshot.forced,
        resolution::evidence*: snapshot.evidence.iter(),
        metadata::supersedes*: snapshot.predecessors.iter(),
        metadata::finished_at: snapshot.finished_at,
    }
}

/// Build one stable decision anchor and its immutable intrinsic genesis.
pub fn decision_fragment(
    decision_id: Id,
    title: impl Into<String>,
    context: Option<String>,
    about: Option<Id>,
    created_at: IntervalValue,
) -> Result<(Fragment, Id)> {
    point_interval(created_at, "decision creation time")?;
    let title = canonical_required(title, "decision title")?;
    let context = context
        .map(|value| canonical_required(value, "decision context"))
        .transpose()?;

    let mut fragment = Fragment::empty();
    let title = fragment.put(title);
    let context = context.map(|value| fragment.put(value));
    let genesis = genesis_record(decision_id, title, context, about, created_at);
    let genesis_id = genesis
        .root()
        .expect("decision genesis has one intrinsic root");
    fragment += decision_anchor_record(decision_id);
    fragment += genesis;
    Ok((fragment, genesis_id))
}

/// Build one independent intrinsic factor occurrence.
pub fn factor_fragment(
    occurrence: Id,
    decision_id: Id,
    side: FactorSide,
    text: impl Into<String>,
    created_at: IntervalValue,
) -> Result<(Fragment, Id)> {
    point_interval(created_at, "factor creation time")?;
    let text = canonical_required(text, "factor text")?;
    let mut fragment = Fragment::empty();
    let text = fragment.put(text);
    let factor = factor_record_fragment(occurrence, decision_id, side, text, created_at);
    let id = factor.root().expect("factor has one intrinsic root");
    fragment += factor;
    Ok((fragment, id))
}

/// Build one complete intrinsic resolution event.
pub fn resolution_fragment(
    decision_id: Id,
    outcome: impl Into<String>,
    result: Option<Id>,
    forced: bool,
    evidence: &[Id],
    predecessors: &[Id],
    finished_at: IntervalValue,
) -> Result<(Fragment, Id)> {
    point_interval(finished_at, "resolution finish time")?;
    let outcome = canonical_required(outcome, "resolution outcome")?;
    let mut fragment = Fragment::empty();
    let snapshot = ResolutionSnapshot {
        id: decision_id,
        decision: decision_id,
        outcome: fragment.put(outcome),
        result,
        forced,
        evidence: sorted_ids(evidence.iter().copied()),
        predecessors: sorted_ids(predecessors.iter().copied()),
        finished_at,
    };
    let record = resolution_record_fragment(&snapshot);
    let id = record.root().expect("resolution has one intrinsic root");
    fragment += record;
    Ok((fragment, id))
}

fn exactly_one<T>(values: Vec<T>, entity: Id, field: &str) -> Result<T> {
    let count = values.len();
    if count != 1 {
        bail!("Decide entity {entity:x} has {count} values for {field}; expected exactly one");
    }
    Ok(values.into_iter().next().unwrap())
}

fn at_most_one<T>(values: Vec<T>, entity: Id, field: &str) -> Result<Option<T>> {
    let count = values.len();
    if count > 1 {
        bail!("Decide entity {entity:x} has {count} values for {field}; expected at most one");
    }
    Ok(values.into_iter().next())
}

pub fn decision_anchors(facts: &TribleSet) -> BTreeSet<Id> {
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: &KIND_DECISION }])).collect()
}

fn ids_of_kind(facts: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: kind }])).collect()
}

/// Canonical factors carry the occurrence coordinate introduced by the
/// native ontology. Legacy random-id pro/con rows deliberately do not; an
/// additive cutover can therefore retain them as provenance without making
/// them part of the live Decide view.
fn canonical_factor_ids(facts: &TribleSet) -> BTreeSet<Id> {
    ids_of_kind(facts, KIND_PRO)
        .union(&ids_of_kind(facts, KIND_CON))
        .copied()
        .filter(|id| {
            facts
                .iter()
                .any(|fact| fact.e() == id && fact.a() == &factor::occurrence.id())
        })
        .collect()
}

pub fn decision_genesis(facts: &TribleSet, id: Id) -> Result<DecisionGenesis> {
    Ok(DecisionGenesis {
        id,
        decision: exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ decide::of: ?value }])).collect(),
            id,
            "decide::of",
        )?,
        title: exactly_one(
            find!(value: TextHandle, pattern!(facts, [{ id @ metadata::name: ?value }])).collect(),
            id,
            "metadata::name",
        )?,
        context: at_most_one(
            find!(value: TextHandle, pattern!(facts, [{ id @ metadata::description: ?value }]))
                .collect(),
            id,
            "metadata::description",
        )?,
        about: at_most_one(
            find!(value: Id, pattern!(facts, [{ id @ decide::about: ?value }])).collect(),
            id,
            "decide::about",
        )?,
        created_at: exactly_one(
            find!(value: IntervalValue, pattern!(facts, [{ id @ metadata::created_at: ?value }]))
                .collect(),
            id,
            "metadata::created_at",
        )?,
    })
}

pub fn genesis_for_decision(facts: &TribleSet, decision_id: Id) -> Result<Option<DecisionGenesis>> {
    let ids: Vec<Id> = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_DECISION_GENESIS, decide::of: &decision_id }])
    )
    .collect();
    match ids.as_slice() {
        [] => Ok(None),
        [id] => Ok(Some(decision_genesis(facts, *id)?)),
        _ => bail!("decision {decision_id:x} has {} genesis records", ids.len()),
    }
}

pub fn factor_record(facts: &TribleSet, id: Id) -> Result<FactorRecord> {
    let pro = find!(
        value: Id,
        pattern!(facts, [{ id @ metadata::tag: ?value }])
    )
    .any(|value| value == KIND_PRO);
    let con = find!(
        value: Id,
        pattern!(facts, [{ id @ metadata::tag: ?value }])
    )
    .any(|value| value == KIND_CON);
    let side = match (pro, con) {
        (true, false) => FactorSide::Pro,
        (false, true) => FactorSide::Con,
        _ => bail!("factor {id:x} must have exactly one pro/con side marker"),
    };
    Ok(FactorRecord {
        id,
        occurrence: exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ factor::occurrence: ?value }])).collect(),
            id,
            "factor::occurrence",
        )?,
        decision: exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ factor::about_decision: ?value }])).collect(),
            id,
            "factor::about_decision",
        )?,
        side,
        text: exactly_one(
            find!(value: TextHandle, pattern!(facts, [{ id @ metadata::name: ?value }])).collect(),
            id,
            "metadata::name",
        )?,
        created_at: exactly_one(
            find!(value: IntervalValue, pattern!(facts, [{ id @ metadata::created_at: ?value }]))
                .collect(),
            id,
            "metadata::created_at",
        )?,
    })
}

pub fn factors_for_decision(facts: &TribleSet, decision_id: Id) -> Result<Vec<FactorRecord>> {
    let mut records = canonical_factor_ids(facts)
        .into_iter()
        .map(|id| validate_factor_intrinsic(facts, id))
        .filter_map(|record| match record {
            Ok(record) if record.decision == decision_id => Some(Ok(record)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>>>()?;
    records.sort_by_key(|record| record.id);
    Ok(records)
}

pub fn resolution_snapshot(facts: &TribleSet, id: Id) -> Result<ResolutionSnapshot> {
    Ok(ResolutionSnapshot {
        id,
        decision: exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ resolution::of: ?value }])).collect(),
            id,
            "resolution::of",
        )?,
        outcome: exactly_one(
            find!(value: TextHandle, pattern!(facts, [{ id @ decide::outcome: ?value }])).collect(),
            id,
            "decide::outcome",
        )?,
        result: at_most_one(
            find!(value: Id, pattern!(facts, [{ id @ resolution::result: ?value }])).collect(),
            id,
            "resolution::result",
        )?,
        forced: exactly_one(
            find!(value: bool, pattern!(facts, [{ id @ resolution::forced: ?value }])).collect(),
            id,
            "resolution::forced",
        )?,
        evidence: sorted_ids(find!(
            value: Id,
            pattern!(facts, [{ id @ resolution::evidence: ?value }])
        )),
        predecessors: sorted_ids(find!(
            value: Id,
            pattern!(facts, [{ id @ metadata::supersedes: ?value }])
        )),
        finished_at: exactly_one(
            find!(value: IntervalValue, pattern!(facts, [{ id @ metadata::finished_at: ?value }]))
                .collect(),
            id,
            "metadata::finished_at",
        )?,
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

fn validate_factor_intrinsic(facts: &TribleSet, id: Id) -> Result<FactorRecord> {
    let record = factor_record(facts, id)?;
    if !decision_anchors(facts).contains(&record.decision) {
        bail!(
            "factor {id:x} names undeclared decision {:x}",
            record.decision
        );
    }
    point_interval(record.created_at, "factor creation time")?;
    ensure_intrinsic(
        id,
        factor_record_fragment(
            record.occurrence,
            record.decision,
            record.side,
            record.text,
            record.created_at,
        ),
        "factor",
    )?;
    Ok(record)
}

/// Validate one resolution in isolation from head selection. This keeps the
/// fork-visible resolver honest even when a caller has not first run whole-
/// catalog validation.
fn validate_resolution_snapshot_intrinsic(facts: &TribleSet, id: Id) -> Result<ResolutionSnapshot> {
    let snapshot = resolution_snapshot(facts, id)?;
    if !decision_anchors(facts).contains(&snapshot.decision) {
        bail!(
            "resolution {id:x} names undeclared decision {:x}",
            snapshot.decision
        );
    }
    point_interval(snapshot.finished_at, "resolution finish time")?;
    ensure_intrinsic(
        id,
        resolution_record_fragment(&snapshot),
        "resolution snapshot",
    )?;

    let mut has_pro = false;
    let mut has_con = false;
    for evidence in &snapshot.evidence {
        let factor = validate_factor_intrinsic(facts, *evidence)
            .with_context(|| format!("validate evidence {evidence:x} for resolution {id:x}"))?;
        if factor.decision != snapshot.decision {
            bail!("resolution {id:x} cites evidence from another decision");
        }
        match factor.side {
            FactorSide::Pro => has_pro = true,
            FactorSide::Con => has_con = true,
        }
    }
    if !snapshot.forced && (!has_pro || !has_con) {
        bail!("non-forced resolution {id:x} must cite at least one pro and one con factor");
    }
    Ok(snapshot)
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

fn resolution_result(facts: &TribleSet, decision_id: Id) -> Result<Resolution> {
    let ids: BTreeSet<Id> = find!(
        id: Id,
        pattern!(facts, [{ ?id @
            metadata::tag: &KIND_RESOLUTION_SNAPSHOT,
            resolution::of: &decision_id,
        }])
    )
    .collect();
    if ids.is_empty() {
        return Ok(Resolution::Missing);
    }
    let mut snapshots = BTreeMap::new();
    let mut graph = BTreeMap::new();
    for id in ids {
        let snapshot = validate_resolution_snapshot_intrinsic(facts, id)?;
        graph.insert(id, snapshot.predecessors.clone());
        snapshots.insert(id, snapshot);
    }
    let heads = dag_heads(
        &graph,
        &format!("resolution track for decision {decision_id:x}"),
    )?;
    match heads.as_slice() {
        [] => bail!("resolution track for decision {decision_id:x} has no head"),
        [id] => Ok(Resolution::Unique(snapshots.remove(id).unwrap())),
        _ => {
            let heads: Vec<_> = heads
                .into_iter()
                .map(|id| snapshots.remove(&id).unwrap())
                .collect();
            // The result tag is part of what agreement means: two heads that
            // read the same to a human but differ in what a gate may do with
            // them are a fork, not an agreement.
            let first = (&heads[0].outcome, &heads[0].result, heads[0].forced);
            if heads
                .iter()
                .all(|snapshot| (&snapshot.outcome, &snapshot.result, snapshot.forced) == first)
            {
                Ok(Resolution::Agreed(heads))
            } else {
                Ok(Resolution::Forked(heads))
            }
        }
    }
}

pub fn resolution(facts: &TribleSet, decision_id: Id) -> Resolution {
    resolution_result(facts, decision_id)
        .unwrap_or_else(|error| Resolution::Invalid(format!("{error:#}")))
}

#[derive(Clone, Copy)]
enum TextRule {
    RequiredCanonical,
}

fn validate_structure(facts: &TribleSet) -> Result<Vec<(TextHandle, TextRule)>> {
    let decisions = decision_anchors(facts);
    let genesis_ids = ids_of_kind(facts, KIND_DECISION_GENESIS);
    let factor_ids = canonical_factor_ids(facts);
    let resolution_ids = ids_of_kind(facts, KIND_RESOLUTION_SNAPSHOT);

    let pro_ids = ids_of_kind(facts, KIND_PRO);
    let con_ids = ids_of_kind(facts, KIND_CON);
    if let Some(id) = factor_ids
        .iter()
        .find(|id| pro_ids.contains(*id) && con_ids.contains(*id))
    {
        bail!("factor {id:x} has both pro and con side markers");
    }

    let mut expected = TribleSet::new();
    let mut texts = Vec::new();
    for &decision_id in &decisions {
        expected += decision_anchor_record(decision_id);
    }

    let mut genesis_by_decision: BTreeMap<Id, Vec<Id>> = BTreeMap::new();
    for id in genesis_ids {
        let genesis = decision_genesis(facts, id)?;
        if !decisions.contains(&genesis.decision) {
            bail!(
                "decision genesis {id:x} names undeclared decision {:x}",
                genesis.decision
            );
        }
        point_interval(genesis.created_at, "decision creation time")?;
        texts.push((genesis.title, TextRule::RequiredCanonical));
        if let Some(context) = genesis.context {
            texts.push((context, TextRule::RequiredCanonical));
        }
        expected += ensure_intrinsic(
            id,
            genesis_record(
                genesis.decision,
                genesis.title,
                genesis.context,
                genesis.about,
                genesis.created_at,
            ),
            "decision genesis",
        )?;
        genesis_by_decision
            .entry(genesis.decision)
            .or_default()
            .push(id);
    }
    for &decision_id in &decisions {
        match genesis_by_decision.get(&decision_id).map(Vec::len) {
            Some(1) => {}
            Some(count) => bail!("decision {decision_id:x} has {count} genesis records"),
            None => bail!("decision {decision_id:x} has no genesis record"),
        }
    }

    for &id in &factor_ids {
        let record = validate_factor_intrinsic(facts, id)?;
        texts.push((record.text, TextRule::RequiredCanonical));
        expected += ensure_intrinsic(
            id,
            factor_record_fragment(
                record.occurrence,
                record.decision,
                record.side,
                record.text,
                record.created_at,
            ),
            "factor",
        )?;
    }

    let mut graphs: BTreeMap<Id, BTreeMap<Id, Vec<Id>>> = BTreeMap::new();
    for id in resolution_ids {
        let snapshot = validate_resolution_snapshot_intrinsic(facts, id)?;
        texts.push((snapshot.outcome, TextRule::RequiredCanonical));

        expected += ensure_intrinsic(
            id,
            resolution_record_fragment(&snapshot),
            "resolution snapshot",
        )?;
        graphs
            .entry(snapshot.decision)
            .or_default()
            .insert(id, snapshot.predecessors);
    }
    for (decision_id, graph) in &graphs {
        let _ = dag_heads(
            graph,
            &format!("resolution track for decision {decision_id:x}"),
        )?;
    }

    let mut native_entities = genesis_by_decision
        .values()
        .flatten()
        .copied()
        .collect::<BTreeSet<_>>();
    native_entities.extend(factor_ids);
    native_entities.extend(graphs.values().flat_map(|graph| graph.keys().copied()));
    let observed: TribleSet = facts
        .iter()
        .filter(|fact| native_entities.contains(fact.e()) || expected.contains(fact))
        .copied()
        .collect();
    if expected != observed {
        let missing = expected.difference(&observed).len();
        let unexpected = observed.difference(&expected).len();
        bail!(
            "Decide catalog is not an exact canonical ontology ({missing} missing, {unexpected} unexpected facts)"
        );
    }
    Ok(texts)
}

fn load_text_from(reader: &PileReader, handle: TextHandle) -> Result<String> {
    let view: View<str> = reader
        .get(handle)
        .with_context(|| format!("read Decide text payload {}", hex::encode(handle.raw)))?;
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
                    "read staged Decide text payload {}",
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
        seen.insert(handle.raw, rule);
    }
    for (raw, _) in seen {
        let value = load_text_overlay(reader, overlay, Inline::new(raw))?;
        if value.is_empty() || value.trim() != value || value.bytes().any(|byte| byte == 0) {
            bail!("Decide canonical text payload is empty, contains NUL, or has surrounding whitespace");
        }
    }
    Ok(())
}

/// Validate one complete materialized authored Decide collection. Forks and
/// uncited concurrent late factors are valid; malformed records are not.
pub fn validate_catalog(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    let texts = validate_structure(facts)?;
    validate_texts(reader, None::<&PileReader>, texts)
}

/// Preflight the exact set union publication would create, including staged
/// attachments, without writing any pile bytes.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::path::PathBuf;

    use crate::storage::{
        initialize_signer, load_signer, open_pile_strict, publish_fragment,
    };
    use crate::schemas::decide::DEFAULT_SCOPE_ID;
    use hifitime::Epoch;

    fn at(second: u8) -> IntervalValue {
        let epoch = Epoch::from_gregorian_utc(2026, 8, 8, 0, 0, second, 0);
        (epoch, epoch).try_to_inline().unwrap()
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        pile: PathBuf,
        key: PathBuf,
    }

    struct TestView {
        facts: TribleSet,
        reader: PileReader,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let pile = directory.path().join("decide.pile");
            let key = directory.path().join("decide.key");
            File::create(&pile).unwrap();
            initialize_signer(&pile, Some(&key)).unwrap();
            Self {
                _directory: directory,
                pile,
                key,
            }
        }

        fn publish(&self, fragment: Fragment) {
            publish_fragment(&self.pile, Some(&self.key), DEFAULT_SCOPE_ID, fragment).unwrap();
        }

        fn view(&self) -> TestView {
            let signer = load_signer(&self.pile, Some(&self.key)).unwrap();
            let pile = open_pile_strict(&self.pile).unwrap();
            let mut collection = crate::collection_names::open(pile, DEFAULT_SCOPE_ID, signer);
            let facts = collection.materialize().unwrap();
            let reader = collection.storage_mut().reader().unwrap();
            collection.into_storage().close().unwrap();
            TestView { facts, reader }
        }
    }

    fn propose(fixture: &Fixture) -> Id {
        let decision = genid().id;
        fixture.publish(
            decision_fragment(decision, "Choose", Some("Context".into()), None, at(0))
                .unwrap()
                .0,
        );
        decision
    }

    fn add_factor(fixture: &Fixture, decision: Id, side: FactorSide, text: &str, at_: u8) -> Id {
        let (fragment, id) = factor_fragment(genid().id, decision, side, text, at(at_)).unwrap();
        fixture.publish(fragment);
        id
    }

    #[test]
    fn intrinsic_records_canonicalize_sets_but_occurrences_remain_distinct() {
        let decision = genid().id;
        let occurrence = genid().id;
        let first = factor_fragment(occurrence, decision, FactorSide::Pro, " yes ", at(1)).unwrap();
        let second = factor_fragment(occurrence, decision, FactorSide::Pro, "yes", at(1)).unwrap();
        assert_eq!(first.1, second.1);
        let distinct =
            factor_fragment(genid().id, decision, FactorSide::Pro, "yes", at(1)).unwrap();
        assert_ne!(first.1, distinct.1);

        let a = genid().id;
        let b = genid().id;
        let first = resolution_fragment(decision, "yes", None, true, &[b, a, b], &[b, a], at(2)).unwrap();
        let second = resolution_fragment(decision, " yes ", None, true, &[a, b], &[a, b], at(2)).unwrap();
        assert_eq!(first.1, second.1);
    }

    #[test]
    fn non_forced_requires_cited_pro_and_con_while_forced_is_explicit() {
        let fixture = Fixture::new();
        let decision = propose(&fixture);
        let pro = add_factor(&fixture, decision, FactorSide::Pro, "benefit", 1);
        let con = add_factor(&fixture, decision, FactorSide::Con, "risk", 2);
        fixture.publish(
            resolution_fragment(decision, "proceed", None, false, &[pro, con], &[], at(3))
                .unwrap()
                .0,
        );
        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        assert!(matches!(
            resolution(&view.facts, decision),
            Resolution::Unique(ResolutionSnapshot { forced: false, .. })
        ));

        let forced = genid().id;
        fixture.publish(
            decision_fragment(forced, "Forced", None, None, at(4))
                .unwrap()
                .0,
        );
        fixture.publish(
            resolution_fragment(forced, "skip", None, true, &[], &[], at(5))
                .unwrap()
                .0,
        );
        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        assert!(matches!(
            resolution(&view.facts, forced),
            Resolution::Unique(ResolutionSnapshot { forced: true, .. })
        ));
    }

    #[test]
    fn concurrent_late_factor_does_not_invalidate_a_resolution() {
        let fixture = Fixture::new();
        let decision = propose(&fixture);
        let pro = add_factor(&fixture, decision, FactorSide::Pro, "benefit", 1);
        let con = add_factor(&fixture, decision, FactorSide::Con, "risk", 2);
        fixture.publish(
            resolution_fragment(decision, "proceed", None, false, &[pro, con], &[], at(3))
                .unwrap()
                .0,
        );
        add_factor(&fixture, decision, FactorSide::Pro, "late concurrent", 3);
        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        assert_eq!(
            factors_for_decision(&view.facts, decision).unwrap().len(),
            3
        );
    }

    #[test]
    fn equal_outcomes_agree_despite_distinct_evidence_time_and_history() {
        let fixture = Fixture::new();
        let decision = propose(&fixture);
        let first_pro = add_factor(&fixture, decision, FactorSide::Pro, "benefit", 1);
        let second_pro = add_factor(&fixture, decision, FactorSide::Pro, "other benefit", 2);
        let con = add_factor(&fixture, decision, FactorSide::Con, "risk", 2);
        let (first, first_id) =
            resolution_fragment(decision, "proceed", None, false, &[first_pro, con], &[], at(3)).unwrap();
        let (second, second_id) =
            resolution_fragment(decision, "proceed", None, false, &[second_pro, con], &[], at(4))
                .unwrap();
        assert_ne!(first_id, second_id);
        fixture.publish(first);
        fixture.publish(second);
        let view = fixture.view();
        let resolved = resolution(&view.facts, decision);
        let heads = resolved.head_ids();
        assert!(matches!(resolved, Resolution::Agreed(ref values) if values.len() == 2));

        fixture.publish(
            resolution_fragment(
                decision,
                "proceed",
                None,
                false,
                &[first_pro, second_pro, con],
                &heads,
                at(5),
            )
            .unwrap()
            .0,
        );
        let view = fixture.view();
        assert!(matches!(
            resolution(&view.facts, decision),
            Resolution::Unique(ResolutionSnapshot { predecessors, .. }) if predecessors == heads
        ));
    }

    #[test]
    fn identical_outcome_with_different_forced_bits_is_a_real_fork() {
        let fixture = Fixture::new();
        let decision = propose(&fixture);
        let pro = add_factor(&fixture, decision, FactorSide::Pro, "benefit", 1);
        let con = add_factor(&fixture, decision, FactorSide::Con, "risk", 2);
        fixture.publish(
            resolution_fragment(decision, "proceed", None, false, &[pro, con], &[], at(3))
                .unwrap()
                .0,
        );
        fixture.publish(
            resolution_fragment(decision, "proceed", None, true, &[pro, con], &[], at(4))
                .unwrap()
                .0,
        );
        let view = fixture.view();
        assert!(matches!(
            resolution(&view.facts, decision),
            Resolution::Forked(ref snapshots)
                if snapshots.len() == 2
                    && snapshots.iter().any(|snapshot| snapshot.forced)
                    && snapshots.iter().any(|snapshot| !snapshot.forced)
        ));
    }

    #[test]
    fn wrong_decision_evidence_makes_resolution_typed_invalid() {
        let first = genid().id;
        let second = genid().id;
        let mut facts = decision_fragment(first, "First", None, None, at(0))
            .unwrap()
            .0;
        facts += decision_fragment(second, "Second", None, None, at(0))
            .unwrap()
            .0;
        let (pro_fragment, pro) =
            factor_fragment(genid().id, second, FactorSide::Pro, "benefit", at(1)).unwrap();
        let (con_fragment, con) =
            factor_fragment(genid().id, second, FactorSide::Con, "risk", at(2)).unwrap();
        facts += pro_fragment;
        facts += con_fragment;
        facts += resolution_fragment(first, "proceed", None, false, &[pro, con], &[], at(3))
            .unwrap()
            .0;

        assert!(matches!(
            resolution(facts.facts(), first),
            Resolution::Invalid(reason) if reason.contains("another decision")
        ));
    }

    #[test]
    fn divergent_outcomes_remain_forked_until_all_heads_are_reconciled() {
        let fixture = Fixture::new();
        let decision = propose(&fixture);
        let pro = add_factor(&fixture, decision, FactorSide::Pro, "benefit", 1);
        let con = add_factor(&fixture, decision, FactorSide::Con, "risk", 2);
        fixture.publish(
            resolution_fragment(decision, "yes", None, false, &[pro, con], &[], at(3))
                .unwrap()
                .0,
        );
        fixture.publish(
            resolution_fragment(decision, "no", None, false, &[pro, con], &[], at(4))
                .unwrap()
                .0,
        );
        let view = fixture.view();
        let fork = resolution(&view.facts, decision);
        let heads = fork.head_ids();
        assert!(matches!(fork, Resolution::Forked(ref values) if values.len() == 2));
        fixture.publish(
            resolution_fragment(decision, "later", None, false, &[pro, con], &heads, at(5))
                .unwrap()
                .0,
        );
        let view = fixture.view();
        assert!(matches!(
            resolution(&view.facts, decision),
            Resolution::Unique(ResolutionSnapshot { predecessors, .. }) if predecessors == heads
        ));
    }

    #[test]
    fn exact_union_preflight_reads_staged_attachments_and_rejects_extra_facts() {
        let fixture = Fixture::new();
        let view = fixture.view();
        let decision = genid().id;
        let (fragment, genesis) = decision_fragment(
            decision,
            "A title whose payload is staged",
            Some("Staged context".into()),
            None,
            at(0),
        )
        .unwrap();
        validate_catalog_union(&view.reader, &view.facts, &fragment).unwrap();

        let mut malformed = fragment;
        malformed += entity! { ExclusiveId::force_ref(&genesis) @ metadata::description: "extra" };
        assert!(validate_catalog_union(&view.reader, &view.facts, &malformed).is_err());
    }
}
