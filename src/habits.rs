//! Collection-native standing intentions.
//!
//! Habits are pulled: reading this model computes what is due now, and never
//! writes a notification queue. Each immutable definition, completion, and
//! state assertion is published as one complete [`Fragment`] to one fixed
//! collection. Pause/resume assertions form a predecessor DAG, so set union
//! keeps concurrent state visible instead of letting time or append order pick
//! a winner.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::collection::{
    simplearchive_union, Collection, CollectionCommit, CollectionDescriptor,
};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::macros::{entity, find, pattern};
use triblespace::prelude::*;

use crate::collection_cutover::{load_signer, open_pile_strict};
use crate::schemas::habit::{
    attrs, Condition, DEFAULT_SCOPE_ID, KIND_DONE_ID, KIND_HABIT_ID, KIND_STATE_ID,
    MAX_LABEL_BYTES, STATE_ACTIVE, STATE_PAUSED,
};

pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

/// Canonical descriptor for the one supported Habit collection.
pub fn descriptor() -> CollectionDescriptor {
    simplearchive_union::descriptor(DEFAULT_SCOPE_ID)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Habit {
    pub id: Id,
    pub label: String,
    /// Author-written source (`every …`, `daily at …`, or `when …`).
    pub condition: String,
    pub nudge: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Completion {
    pub id: Id,
    pub habit: Id,
    pub completed_at: IntervalValue,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DeclaredState {
    Active,
    Paused,
}

impl DeclaredState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => STATE_ACTIVE,
            Self::Paused => STATE_PAUSED,
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            STATE_ACTIVE => Ok(Self::Active),
            STATE_PAUSED => Ok(Self::Paused),
            other => bail!("unknown Habit state {other:?}; expected `active` or `paused`"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateAssertion {
    pub id: Id,
    pub habit: Id,
    pub state: DeclaredState,
    pub predecessors: Vec<Id>,
    pub asserted_at: IntervalValue,
}

/// Fork-visible activation state for one standing intention.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Activation {
    /// No assertion is also active; the vector is then empty.
    Active(Vec<StateAssertion>),
    Paused(Vec<StateAssertion>),
    /// Maximal assertions disagree. Every head remains available to a later
    /// reconciliation assertion.
    Forked(Vec<StateAssertion>),
}

impl Activation {
    pub fn head_ids(&self) -> Vec<Id> {
        match self {
            Self::Active(heads) | Self::Paused(heads) | Self::Forked(heads) => {
                heads.iter().map(|head| head.id).collect()
            }
        }
    }

    pub fn declared(&self) -> Option<DeclaredState> {
        match self {
            Self::Active(_) => Some(DeclaredState::Active),
            Self::Paused(_) => Some(DeclaredState::Paused),
            Self::Forked(_) => None,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Catalog {
    habits: BTreeMap<Id, Habit>,
    completions: BTreeMap<Id, Completion>,
    assertions: BTreeMap<Id, StateAssertion>,
}

impl Catalog {
    pub fn habits(&self) -> impl Iterator<Item = &Habit> {
        self.habits.values()
    }

    pub fn habit(&self, id: Id) -> Option<&Habit> {
        self.habits.get(&id)
    }

    pub fn completions(&self) -> impl Iterator<Item = &Completion> {
        self.completions.values()
    }

    pub fn assertions(&self) -> impl Iterator<Item = &StateAssertion> {
        self.assertions.values()
    }

    /// Case-insensitive command-address lookup. Several results are a visible
    /// concurrent-definition conflict; callers must not choose one.
    pub fn labelled(&self, label: &str) -> Vec<&Habit> {
        let label = label.trim().to_ascii_lowercase();
        self.habits
            .values()
            .filter(|habit| habit.label.to_ascii_lowercase() == label)
            .collect()
    }

    pub fn activation(&self, habit: Id) -> Result<Activation> {
        if !self.habits.contains_key(&habit) {
            bail!("unknown Habit {habit:x}");
        }
        let graph: BTreeMap<Id, Vec<Id>> = self
            .assertions
            .values()
            .filter(|assertion| assertion.habit == habit)
            .map(|assertion| (assertion.id, assertion.predecessors.clone()))
            .collect();
        let heads = dag_heads(&graph, &format!("state track for Habit {habit:x}"))?;
        if heads.is_empty() {
            return Ok(Activation::Active(Vec::new()));
        }
        let heads: Vec<_> = heads
            .into_iter()
            .map(|id| self.assertions[&id].clone())
            .collect();
        let first = heads[0].state;
        if heads.iter().all(|head| head.state == first) {
            return Ok(match first {
                DeclaredState::Active => Activation::Active(heads),
                DeclaredState::Paused => Activation::Paused(heads),
            });
        }
        Ok(Activation::Forked(heads))
    }

    pub fn rows(&self) -> Result<Vec<HabitRow>> {
        let mut rows = Vec::with_capacity(self.habits.len());
        for habit in self.habits.values() {
            let mut completed_at = self
                .completions
                .values()
                .filter(|completion| completion.habit == habit.id)
                .map(|completion| interval_seconds(completion.completed_at, "completion time"))
                .collect::<Result<Vec<_>>>()?;
            completed_at.sort_unstable();
            completed_at.dedup();
            rows.push(HabitRow {
                id: habit.id,
                label: habit.label.clone(),
                condition: habit.condition.clone(),
                nudge: habit.nudge.clone(),
                activation: self.activation(habit.id)?,
                completed_at,
            });
        }
        rows.sort_by(|left, right| (&left.label, left.id).cmp(&(&right.label, right.id)));
        Ok(rows)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HabitRow {
    pub id: Id,
    pub label: String,
    pub condition: String,
    pub nudge: String,
    pub activation: Activation,
    /// Complete set of completion points, represented in integral TAI seconds.
    pub completed_at: Vec<i64>,
}

impl HabitRow {
    pub fn last_done(&self) -> Option<i64> {
        self.completed_at.iter().copied().max()
    }

    /// Earliest wall-clock second at which the current completion set can stop
    /// cooling. It is scheduling information, not a state winner.
    pub fn next_cooldown_at(&self) -> Result<Option<i64>, String> {
        let condition = Condition::parse(&self.condition)?;
        Ok(self
            .last_done()
            .map(|done| done.saturating_add(condition.cooldown_secs)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum State {
    Due,
    Cooling,
    Waiting,
    Paused,
    Forked(Vec<(Id, DeclaredState)>),
    Unparseable(String),
    Failed(String),
}

impl State {
    pub const fn is_due(&self) -> bool {
        matches!(self, Self::Due)
    }

    pub const fn word(&self) -> &'static str {
        match self {
            Self::Due => "DUE",
            Self::Cooling => "cooling",
            Self::Waiting => "waiting",
            Self::Paused => "paused",
            Self::Forked(_) => "FORKED",
            Self::Unparseable(_) => "BROKEN",
            Self::Failed(_) => "ERROR",
        }
    }
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

fn canonical_label(value: impl Into<String>) -> Result<String> {
    let value = canonical_required(value, "Habit label")?;
    if value.len() > MAX_LABEL_BYTES {
        bail!(
            "Habit label must be at most {MAX_LABEL_BYTES} bytes, got {}",
            value.len()
        );
    }
    Ok(value)
}

fn sorted_ids(values: impl IntoIterator<Item = Id>) -> Vec<Id> {
    let mut values: Vec<_> = values.into_iter().collect();
    values.sort_unstable();
    values.dedup();
    values
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

fn interval_seconds(value: IntervalValue, field: &str) -> Result<i64> {
    point_interval(value, field)?;
    let (nanoseconds, _): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode {field}: {error:?}"))?;
    i64::try_from(nanoseconds / 1_000_000_000)
        .map_err(|_| anyhow!("{field} lies outside the supported second range"))
}

fn habit_record(label: &str, condition: TextHandle, nudge: TextHandle) -> Fragment {
    entity! { _ @
        metadata::tag: &KIND_HABIT_ID,
        attrs::label: label,
        attrs::condition: condition,
        attrs::nudge: nudge,
    }
}

fn completion_record(habit: Id, completed_at: IntervalValue) -> Fragment {
    entity! { _ @
        metadata::tag: &KIND_DONE_ID,
        attrs::of: &habit,
        metadata::created_at: completed_at,
    }
}

fn state_record(
    habit: Id,
    state: DeclaredState,
    predecessors: &[Id],
    asserted_at: IntervalValue,
) -> Fragment {
    entity! { _ @
        metadata::tag: &KIND_STATE_ID,
        attrs::of: &habit,
        attrs::state: state.as_str(),
        metadata::supersedes*: predecessors.iter(),
        metadata::created_at: asserted_at,
    }
}

/// Build one complete, intrinsically identified standing intention.
pub fn habit_fragment(
    label: impl Into<String>,
    condition: impl Into<String>,
    nudge: impl Into<String>,
) -> Result<(Fragment, Id)> {
    let label = canonical_label(label)?;
    let condition = canonical_required(condition, "Habit condition")?;
    Condition::parse(&condition).map_err(|error| anyhow!(error))?;
    let nudge = canonical_required(nudge, "Habit nudge")?;

    let mut fragment = Fragment::empty();
    let condition = fragment.put(condition);
    let nudge = fragment.put(nudge);
    let record = habit_record(&label, condition, nudge);
    let id = record
        .root()
        .expect("Habit definition has one intrinsic root");
    fragment += record;
    Ok((fragment, id))
}

/// Build one complete intrinsic completion occurrence.
pub fn completion_fragment(habit: Id, completed_at: IntervalValue) -> Result<(Fragment, Id)> {
    point_interval(completed_at, "Habit completion time")?;
    let fragment = completion_record(habit, completed_at);
    let id = fragment
        .root()
        .expect("Habit completion has one intrinsic root");
    Ok((fragment, id))
}

/// Build one complete intrinsic state assertion. Callers normally cite every
/// currently maximal assertion; racing callers may still create a visible
/// fork, which a later assertion can reconcile by citing all heads.
pub fn state_fragment(
    habit: Id,
    state: DeclaredState,
    predecessors: &[Id],
    asserted_at: IntervalValue,
) -> Result<(Fragment, Id)> {
    point_interval(asserted_at, "Habit state assertion time")?;
    let predecessors = sorted_ids(predecessors.iter().copied());
    let fragment = state_record(habit, state, &predecessors, asserted_at);
    let id = fragment
        .root()
        .expect("Habit state assertion has one intrinsic root");
    Ok((fragment, id))
}

fn exactly_one<T>(values: Vec<T>, entity: Id, field: &str) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "Habit entity {entity:x} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(values.into_iter().next().unwrap())
}

fn ids_of_kind(facts: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: kind }])).collect()
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

fn ensure_exact_entity(facts: &TribleSet, id: Id, expected: &TribleSet, label: &str) -> Result<()> {
    let actual = facts.iter().filter(|fact| fact.e() == &id).count();
    if actual != expected.len() || !expected.difference(facts).is_empty() {
        bail!(
            "{label} {id:x} has {actual} facts; expected exactly {}",
            expected.len()
        );
    }
    Ok(())
}

#[derive(Clone)]
struct RawHabit {
    id: Id,
    label: String,
    condition: TextHandle,
    nudge: TextHandle,
}

#[derive(Clone)]
struct RawCatalog {
    habits: BTreeMap<Id, RawHabit>,
    completions: BTreeMap<Id, Completion>,
    assertions: BTreeMap<Id, StateAssertion>,
}

fn parse_habit(facts: &TribleSet, id: Id) -> Result<RawHabit> {
    Ok(RawHabit {
        id,
        label: exactly_one(
            find!(value: String, pattern!(facts, [{ id @ attrs::label: ?value }])).collect(),
            id,
            "habit::label",
        )?,
        condition: exactly_one(
            find!(value: TextHandle, pattern!(facts, [{ id @ attrs::condition: ?value }]))
                .collect(),
            id,
            "habit::condition",
        )?,
        nudge: exactly_one(
            find!(value: TextHandle, pattern!(facts, [{ id @ attrs::nudge: ?value }])).collect(),
            id,
            "habit::nudge",
        )?,
    })
}

fn parse_completion(facts: &TribleSet, id: Id) -> Result<Completion> {
    Ok(Completion {
        id,
        habit: exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ attrs::of: ?value }])).collect(),
            id,
            "habit::of",
        )?,
        completed_at: exactly_one(
            find!(value: IntervalValue, pattern!(facts, [{ id @ metadata::created_at: ?value }]))
                .collect(),
            id,
            "metadata::created_at",
        )?,
    })
}

fn parse_assertion(facts: &TribleSet, id: Id) -> Result<StateAssertion> {
    let state = exactly_one(
        find!(value: String, pattern!(facts, [{ id @ attrs::state: ?value }])).collect(),
        id,
        "habit::state",
    )?;
    Ok(StateAssertion {
        id,
        habit: exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ attrs::of: ?value }])).collect(),
            id,
            "habit::of",
        )?,
        state: DeclaredState::parse(&state)?,
        predecessors: sorted_ids(find!(
            value: Id,
            pattern!(facts, [{ id @ metadata::supersedes: ?value }])
        )),
        asserted_at: exactly_one(
            find!(value: IntervalValue, pattern!(facts, [{ id @ metadata::created_at: ?value }]))
                .collect(),
            id,
            "metadata::created_at",
        )?,
    })
}

fn validate_structure(facts: &TribleSet) -> Result<RawCatalog> {
    let habit_ids = ids_of_kind(facts, KIND_HABIT_ID);
    let completion_ids = ids_of_kind(facts, KIND_DONE_ID);
    let assertion_ids = ids_of_kind(facts, KIND_STATE_ID);

    let mut all_ids = BTreeSet::new();
    for (label, ids) in [
        ("Habit definition", &habit_ids),
        ("Habit completion", &completion_ids),
        ("Habit state assertion", &assertion_ids),
    ] {
        for id in ids {
            if !all_ids.insert(*id) {
                bail!("entity {id:x} belongs to more than one Habit record kind ({label})");
            }
        }
    }

    let mut habits = BTreeMap::new();
    for id in habit_ids {
        let raw = parse_habit(facts, id)?;
        let canonical = canonical_label(raw.label.clone())?;
        if canonical != raw.label {
            bail!("Habit {id:x} label is not canonical");
        }
        let expected = habit_record(&raw.label, raw.condition, raw.nudge);
        if expected.root() != Some(id) {
            // Additive cutovers retain the exact random-id legacy record next
            // to its intrinsic native shadow. It remains durable evidence but
            // is not part of the live Habit view.
            continue;
        }
        ensure_exact_entity(facts, id, expected.facts(), "Habit definition")?;
        habits.insert(id, raw);
    }

    let mut completions = BTreeMap::new();
    for id in completion_ids {
        let completion = parse_completion(facts, id)?;
        let expected = completion_record(completion.habit, completion.completed_at);
        if expected.root() != Some(id) {
            continue;
        }
        if !habits.contains_key(&completion.habit) {
            bail!(
                "Habit completion {id:x} names missing definition {:x}",
                completion.habit
            );
        }
        point_interval(completion.completed_at, "Habit completion time")?;
        ensure_exact_entity(facts, id, expected.facts(), "Habit completion")?;
        completions.insert(id, completion);
    }

    let mut assertions = BTreeMap::new();
    for id in assertion_ids {
        let assertion = parse_assertion(facts, id)?;
        let expected = state_record(
            assertion.habit,
            assertion.state,
            &assertion.predecessors,
            assertion.asserted_at,
        );
        if expected.root() != Some(id) {
            continue;
        }
        if !habits.contains_key(&assertion.habit) {
            bail!(
                "Habit state assertion {id:x} names missing definition {:x}",
                assertion.habit
            );
        }
        point_interval(assertion.asserted_at, "Habit state assertion time")?;
        ensure_exact_entity(facts, id, expected.facts(), "Habit state assertion")?;
        assertions.insert(id, assertion);
    }

    let mut graphs = BTreeMap::<Id, BTreeMap<Id, Vec<Id>>>::new();
    for assertion in assertions.values() {
        graphs
            .entry(assertion.habit)
            .or_default()
            .insert(assertion.id, assertion.predecessors.clone());
    }
    for (habit, graph) in &graphs {
        let _ = dag_heads(graph, &format!("state track for Habit {habit:x}"))?;
    }

    Ok(RawCatalog {
        habits,
        completions,
        assertions,
    })
}

fn reaches(start: Id, target: Id, graph: &BTreeMap<Id, Vec<Id>>) -> bool {
    let mut pending = vec![start];
    let mut seen = BTreeSet::new();
    while let Some(node) = pending.pop() {
        if node == target {
            return true;
        }
        if seen.insert(node) {
            pending.extend(graph.get(&node).into_iter().flatten().copied());
        }
    }
    false
}

fn dag_heads(graph: &BTreeMap<Id, Vec<Id>>, label: &str) -> Result<Vec<Id>> {
    for (&node, predecessors) in graph {
        for predecessor in predecessors {
            if !graph.contains_key(predecessor) {
                bail!("{label} node {node:x} cites missing predecessor {predecessor:x}");
            }
        }
        for (index, left) in predecessors.iter().enumerate() {
            for right in &predecessors[index + 1..] {
                if reaches(*left, *right, graph) || reaches(*right, *left, graph) {
                    bail!(
                        "{label} node {node:x} has non-antichain predecessors {left:x} and {right:x}"
                    );
                }
            }
        }
    }

    fn visit(
        node: Id,
        graph: &BTreeMap<Id, Vec<Id>>,
        visiting: &mut BTreeSet<Id>,
        visited: &mut BTreeSet<Id>,
        label: &str,
    ) -> Result<()> {
        if visited.contains(&node) {
            return Ok(());
        }
        if !visiting.insert(node) {
            bail!("{label} contains a predecessor cycle at {node:x}");
        }
        for predecessor in &graph[&node] {
            visit(*predecessor, graph, visiting, visited, label)?;
        }
        visiting.remove(&node);
        visited.insert(node);
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for node in graph.keys().copied() {
        visit(node, graph, &mut visiting, &mut visited, label)?;
    }

    let superseded: BTreeSet<_> = graph
        .values()
        .flat_map(|predecessors| predecessors.iter().copied())
        .collect();
    Ok(graph
        .keys()
        .filter(|id| !superseded.contains(*id))
        .copied()
        .collect())
}

fn load_text(reader: &PileReader, handle: TextHandle, field: &str) -> Result<String> {
    let value: View<str> = reader
        .get(handle)
        .with_context(|| format!("read Habit {field} payload {}", hex::encode(handle.raw)))?;
    Ok(value.to_string())
}

fn load_text_overlay<Overlay>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    handle: TextHandle,
    field: &str,
) -> Result<String>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    if let Some(overlay) = overlay {
        if overlay
            .metadata(handle)
            .expect("in-memory Habit attachment lookup is infallible")
            .is_some()
        {
            let value: View<str> = overlay.get(handle).with_context(|| {
                format!(
                    "read staged Habit {field} payload {}",
                    hex::encode(handle.raw)
                )
            })?;
            return Ok(value.to_string());
        }
    }
    load_text(reader, handle, field)
}

fn decode_catalog<Overlay>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    raw: RawCatalog,
) -> Result<Catalog>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    let mut texts = HashMap::<[u8; 32], String>::new();
    let mut habits = BTreeMap::new();
    for raw_habit in raw.habits.values() {
        let condition = if let Some(value) = texts.get(&raw_habit.condition.raw) {
            value.clone()
        } else {
            let value = load_text_overlay(reader, overlay, raw_habit.condition, "condition")?;
            texts.insert(raw_habit.condition.raw, value.clone());
            value
        };
        let canonical_condition = canonical_required(condition.clone(), "Habit condition payload")?;
        if canonical_condition != condition {
            bail!("Habit {} condition payload is not canonical", raw_habit.id);
        }
        let condition = canonical_condition;
        Condition::parse(&condition)
            .map_err(|error| anyhow!("Habit {} condition: {error}", raw_habit.id))?;

        let nudge = if let Some(value) = texts.get(&raw_habit.nudge.raw) {
            value.clone()
        } else {
            let value = load_text_overlay(reader, overlay, raw_habit.nudge, "nudge")?;
            texts.insert(raw_habit.nudge.raw, value.clone());
            value
        };
        let canonical_nudge = canonical_required(nudge.clone(), "Habit nudge payload")?;
        if canonical_nudge != nudge {
            bail!("Habit {} nudge payload is not canonical", raw_habit.id);
        }
        let nudge = canonical_nudge;
        habits.insert(
            raw_habit.id,
            Habit {
                id: raw_habit.id,
                label: raw_habit.label.clone(),
                condition,
                nudge,
            },
        );
    }
    Ok(Catalog {
        habits,
        completions: raw.completions,
        assertions: raw.assertions,
    })
}

/// Strictly validate and decode one complete materialized Habit collection.
pub fn load_catalog(reader: &PileReader, facts: &TribleSet) -> Result<Catalog> {
    let raw = validate_structure(facts)?;
    decode_catalog(reader, None::<&PileReader>, raw)
}

pub fn validate_catalog(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    load_catalog(reader, facts).map(drop)
}

/// Preflight the exact set union a publication would create, resolving blob
/// handles from the staged complete fragment before it is appended.
pub fn validate_catalog_union(
    reader: &PileReader,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<TribleSet> {
    let mut union = current.clone();
    union += fragment.facts().clone();
    let raw = validate_structure(&union)?;
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .reader()
        .expect("Habit MemoryBlobStore reader creation is infallible");
    decode_catalog(reader, Some(&overlay), raw)?;
    Ok(union)
}

/// Validate one authored publication unit independently of ambient catalog
/// facts. Every unit is exactly one intrinsic record; definition payloads must
/// be carried by the fragment itself.
pub fn validate_publication_fragment(fragment: &Fragment) -> Result<()> {
    let id = fragment
        .root()
        .ok_or_else(|| anyhow!("Habit publication must export one intrinsic root"))?;
    if fragment.facts().iter().any(|fact| fact.e() != &id) {
        bail!("Habit publication {id:x} contains facts owned by another entity");
    }
    let facts = fragment.facts();
    let is_habit = ids_of_kind(facts, KIND_HABIT_ID).contains(&id);
    let is_completion = ids_of_kind(facts, KIND_DONE_ID).contains(&id);
    let is_assertion = ids_of_kind(facts, KIND_STATE_ID).contains(&id);
    if usize::from(is_habit) + usize::from(is_completion) + usize::from(is_assertion) != 1 {
        bail!("Habit publication {id:x} must carry exactly one recognized kind");
    }

    let expected = if is_habit {
        let raw = parse_habit(facts, id)?;
        let label = canonical_label(raw.label.clone())?;
        if label != raw.label {
            bail!("Habit {id:x} label is not canonical");
        }
        let expected = ensure_intrinsic(
            id,
            habit_record(&raw.label, raw.condition, raw.nudge),
            "Habit definition",
        )?;
        let mut local = fragment.clone();
        let reader = local
            .blobs_mut()
            .reader()
            .expect("Habit MemoryBlobStore reader creation is infallible");
        let condition: View<str> = reader.get(raw.condition).map_err(|_| {
            anyhow!(
                "complete Habit definition {id:x} is missing condition payload {}",
                hex::encode(raw.condition.raw)
            )
        })?;
        let condition_source = condition.to_string();
        let condition = canonical_required(condition_source.clone(), "Habit condition payload")?;
        if condition != condition_source {
            bail!("Habit {id:x} condition payload is not canonical");
        }
        Condition::parse(&condition).map_err(|error| anyhow!(error))?;
        let nudge: View<str> = reader.get(raw.nudge).map_err(|_| {
            anyhow!(
                "complete Habit definition {id:x} is missing nudge payload {}",
                hex::encode(raw.nudge.raw)
            )
        })?;
        let nudge_source = nudge.to_string();
        let nudge = canonical_required(nudge_source.clone(), "Habit nudge payload")?;
        if nudge != nudge_source {
            bail!("Habit {id:x} nudge payload is not canonical");
        }
        expected
    } else if is_completion {
        let completion = parse_completion(facts, id)?;
        point_interval(completion.completed_at, "Habit completion time")?;
        ensure_intrinsic(
            id,
            completion_record(completion.habit, completion.completed_at),
            "Habit completion",
        )?
    } else {
        let assertion = parse_assertion(facts, id)?;
        point_interval(assertion.asserted_at, "Habit state assertion time")?;
        ensure_intrinsic(
            id,
            state_record(
                assertion.habit,
                assertion.state,
                &assertion.predecessors,
                assertion.asserted_at,
            ),
            "Habit state assertion",
        )?
    };
    if expected != *facts {
        bail!("Habit publication {id:x} is not one complete canonical record");
    }
    Ok(())
}

/// Publish one complete Habit record to the fixed canonical collection.
/// Exact fragment replay is idempotent; distinct concurrent assertions coexist.
pub fn publish(
    pile_path: &Path,
    key_path: Option<&Path>,
    fragment: Fragment,
) -> Result<CollectionCommit> {
    validate_publication_fragment(&fragment)?;
    let signer = load_signer(pile_path, key_path)?;
    let pile = open_pile_strict(pile_path)?;
    let mut collection = Collection::new(pile, DEFAULT_SCOPE_ID, signer);
    let result = (|| {
        let current = collection
            .materialize()
            .context("materialize native Habit collection")?;
        let reader = collection
            .storage_mut()
            .reader()
            .context("open Habit attachment reader")?;
        validate_catalog_union(&reader, &current, &fragment)
            .context("preflight complete Habit publication")?;
        collection
            .commit(fragment)
            .context("commit complete Habit record")
    })();
    finish_pile(collection.into_storage(), result)
}

/// Materialize the fixed collection through its durable signer and return the
/// strict decoded set value.
pub fn read_catalog(pile_path: &Path, key_path: Option<&Path>) -> Result<Catalog> {
    let signer = load_signer(pile_path, key_path)?;
    let pile = open_pile_strict(pile_path)?;
    let mut collection = Collection::new(pile, DEFAULT_SCOPE_ID, signer);
    let result = (|| {
        let facts = collection
            .materialize()
            .context("materialize native Habit collection")?;
        let reader = collection
            .storage_mut()
            .reader()
            .context("open Habit attachment reader")?;
        load_catalog(&reader, &facts).context("validate native Habit catalog")
    })();
    finish_pile(collection.into_storage(), result)
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    match (result, pile.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(anyhow!("close Habit pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Habit pile also failed: {close_error}")))
        }
    }
}

/// Run the predicate from the fixed directory supplied by the caller.
pub fn condition_holds(command: &str, at: &Path) -> std::result::Result<bool, String> {
    // A timer-driven predicate must not stream arbitrary output into whoever
    // happens to be reading Orient. Capture it, and retain stderr only for the
    // one shell outcome which means the predicate itself is broken.
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(at)
        .output()
        .map_err(|error| format!("running {command:?}: {error}"))?;
    if output.status.code() == Some(127) {
        return Err(format!(
            "command not found: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.status.success())
}

/// Evaluate one standing intention against a wall-clock second.
pub fn evaluate(row: &HabitRow, now_secs: i64, at: &Path) -> State {
    match &row.activation {
        Activation::Paused(_) => return State::Paused,
        Activation::Forked(heads) => {
            return State::Forked(heads.iter().map(|head| (head.id, head.state)).collect())
        }
        Activation::Active(_) => {}
    }
    let condition = match Condition::parse(&row.condition) {
        Ok(condition) => condition,
        Err(error) => return State::Unparseable(error),
    };
    // Cooldown first: it avoids spawning a predicate while a recent
    // completion already proves the intention satisfied.
    if !condition.cooled_down(now_secs, row.completed_at.iter().copied()) {
        return State::Cooling;
    }
    match condition_holds(&condition.command, at) {
        Ok(true) => State::Due,
        Ok(false) => State::Waiting,
        Err(error) => State::Failed(error),
    }
}

/// Shell predicates are evaluated relative to the directory containing the
/// pile, not whichever working directory happened to launch a watcher.
pub fn evaluation_dir(pile: &Path) -> std::path::PathBuf {
    pile.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_owned()
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::PathBuf;

    use hifitime::Epoch;

    use crate::collection_cutover::{initialize_signer, load_signer};

    use super::*;

    fn at(seconds: f64) -> IntervalValue {
        let epoch = Epoch::from_unix_seconds(seconds);
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
            let pile = directory.path().join("habit.pile");
            let key = directory.path().join("habit.key");
            File::create(&pile).unwrap();
            initialize_signer(&pile, Some(&key)).unwrap();
            Self {
                _directory: directory,
                pile,
                key,
            }
        }

        fn publish(&self, fragment: Fragment) -> CollectionCommit {
            publish(&self.pile, Some(&self.key), fragment).unwrap()
        }

        fn catalog(&self) -> Catalog {
            read_catalog(&self.pile, Some(&self.key)).unwrap()
        }
    }

    fn row(condition: &str, completed_at: &[i64], activation: Activation) -> HabitRow {
        HabitRow {
            id: Id::new([1; 16]).unwrap(),
            label: "test".to_owned(),
            condition: condition.to_owned(),
            nudge: "do it".to_owned(),
            activation,
            completed_at: completed_at.to_vec(),
        }
    }

    #[test]
    fn new_true_and_false_conditions_are_due_and_not_due() {
        let active = Activation::Active(Vec::new());
        assert_eq!(
            evaluate(
                &row("every 1h", &[], active.clone()),
                10_000,
                Path::new(".")
            ),
            State::Due
        );
        assert_eq!(
            evaluate(&row("when exit 1", &[], active), 10_000, Path::new(".")),
            State::Waiting
        );
    }

    #[test]
    fn cooldown_is_measured_from_completion_not_observation() {
        let row = row("every 1h", &[1_000, 9_000], Activation::Active(Vec::new()));
        for _ in 0..3 {
            assert_eq!(evaluate(&row, 10_000, Path::new(".")), State::Cooling);
        }
        assert_eq!(evaluate(&row, 12_600, Path::new(".")), State::Due);
        assert_eq!(row.next_cooldown_at().unwrap(), Some(12_600));
    }

    #[test]
    fn intrinsic_definition_and_exact_retry_are_idempotent() {
        let fixture = Fixture::new();
        let (fragment, id) = habit_fragment("journal", "every 1d", "write the journal").unwrap();
        let first = fixture.publish(fragment.clone());
        let after_first = std::fs::metadata(&fixture.pile).unwrap().len();
        let replay = fixture.publish(fragment);
        assert_eq!(replay, first);
        assert_eq!(std::fs::metadata(&fixture.pile).unwrap().len(), after_first);
        let catalog = fixture.catalog();
        assert_eq!(
            catalog.habits().map(|habit| habit.id).collect::<Vec<_>>(),
            [id]
        );

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let collection = Collection::new(pile, DEFAULT_SCOPE_ID, signer);
        assert_eq!(collection.descriptor(), &descriptor());
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn concurrent_state_assertions_stay_forked_until_reconciled() {
        let fixture = Fixture::new();
        let (definition, habit) = habit_fragment("journal", "every 1h", "write").unwrap();
        fixture.publish(definition);

        // Two writers observed the same empty frontier and asserted different
        // states. Sequential publication here simulates their later set union.
        let (paused, _) = state_fragment(habit, DeclaredState::Paused, &[], at(1.0)).unwrap();
        let (active, _) = state_fragment(habit, DeclaredState::Active, &[], at(2.0)).unwrap();
        fixture.publish(paused);
        fixture.publish(active);
        let catalog = fixture.catalog();
        let fork = catalog.activation(habit).unwrap();
        let heads = fork.head_ids();
        assert!(matches!(fork, Activation::Forked(ref values) if values.len() == 2));

        let (joined, _) = state_fragment(habit, DeclaredState::Active, &heads, at(3.0)).unwrap();
        fixture.publish(joined);
        assert!(matches!(
            fixture.catalog().activation(habit).unwrap(),
            Activation::Active(ref values) if values.len() == 1 && values[0].predecessors == heads
        ));
    }

    #[test]
    fn concurrent_definition_conflicts_are_visible_not_timestamp_arbitrated() {
        let fixture = Fixture::new();
        let (daily, daily_id) = habit_fragment("hygiene", "every 1d", "inspect branches").unwrap();
        let (weekly, weekly_id) =
            habit_fragment("hygiene", "every 7d", "inspect branches").unwrap();
        fixture.publish(daily);
        fixture.publish(weekly);
        let catalog = fixture.catalog();
        assert_eq!(
            catalog
                .labelled("HYGIENE")
                .into_iter()
                .map(|habit| habit.id)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([daily_id, weekly_id])
        );
    }

    #[test]
    fn strict_catalog_rejects_extra_facts_and_dangling_events() {
        let mut fragment = habit_fragment("journal", "every 1h", "write").unwrap().0;
        let id = fragment.root().unwrap();
        fragment += entity! { ExclusiveId::force_ref(&id) @ metadata::supersedes: &id };
        assert!(validate_publication_fragment(&fragment).is_err());

        let dangling = completion_fragment(Id::new([9; 16]).unwrap(), at(1.0))
            .unwrap()
            .0;
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("empty.pile");
        File::create(&pile_path).unwrap();
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let reader = pile.reader().unwrap();
        let error = validate_catalog_union(&reader, &TribleSet::new(), &fragment).unwrap_err();
        assert!(format!("{error:#}").contains("expected exactly"));
        let error = validate_catalog_union(&reader, &TribleSet::new(), &dangling).unwrap_err();
        assert!(format!("{error:#}").contains("missing definition"));
        pile.close().unwrap();
    }

    #[test]
    fn additive_legacy_records_are_inert_beside_exact_intrinsic_shadows() {
        let (mut fragment, native) = habit_fragment("journal", "every 1h", "write").unwrap();
        let raw = parse_habit(fragment.facts(), native).unwrap();
        let legacy = Id::new([0xA7; 16]).unwrap();
        assert_ne!(legacy, native);
        fragment += entity! { ExclusiveId::force_ref(&legacy) @
            metadata::tag: &KIND_HABIT_ID,
            attrs::label: raw.label.as_str(),
            attrs::condition: raw.condition,
            attrs::nudge: raw.nudge,
            metadata::created_at: at(1.0),
        };

        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("empty.pile");
        File::create(&pile_path).unwrap();
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let reader = pile.reader().unwrap();
        let union = validate_catalog_union(&reader, &TribleSet::new(), &fragment).unwrap();
        let raw = validate_structure(&union).unwrap();
        assert_eq!(raw.habits.keys().copied().collect::<Vec<_>>(), [native]);
        assert!(union.iter().any(|fact| fact.e() == &legacy));
        pile.close().unwrap();
    }

    #[test]
    fn publication_definition_must_carry_its_own_payloads() {
        let missing_condition = TextHandle::new([3; 32]);
        let missing_nudge = TextHandle::new([4; 32]);
        let bare = habit_record("journal", missing_condition, missing_nudge);
        let error = validate_publication_fragment(&bare).unwrap_err();
        assert!(format!("{error:#}").contains("missing condition payload"));
    }
}
