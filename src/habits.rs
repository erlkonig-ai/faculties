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
use ed25519_dalek::VerifyingKey;
use triblespace::core::collection::{CollectionCommit, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::{BlobStoreGet, BlobStoreMeta, SnapshotSource};
use triblespace::macros::{entity, find, pattern};
use triblespace::prelude::*;

use crate::legacy_hint::open_scope;
use crate::schemas::habit::{
    attrs, Condition, DEFAULT_SCOPE_ID, KIND_DONE_ID, KIND_HABIT_ID, KIND_STATE_ID,
    MAX_LABEL_BYTES, SCRIPT_TOKEN, STATE_ACTIVE, STATE_PAUSED,
};
use crate::storage::{load_signer, open_pile_strict};

pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
pub type ScriptHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;
pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

/// Canonical descriptor for the one supported Habit collection.
///
/// Named `"habit"` within `team`, which is the team's ROOT key rather than the
/// key that signs commits. It is a parameter because they coincide only for a
/// team of one, and defaulting would root this collection at whichever key
/// happened to be writing.
pub fn descriptor(team: VerifyingKey) -> Fragment {
    crate::collection_names::root_descriptor(DEFAULT_SCOPE_ID, team)
}

/// Content identity of the Habit collection this pile roots.
///
/// Written out rather than reached for: core deliberately offers no helper for
/// hashing a descriptor it did not store, because a handle computed beside a
/// store instead of by it can name a collection whose descriptor is absent.
/// This one is only ever printed.
pub fn collection_handle(
    pile: &Path,
    key: Option<&Path>,
) -> Result<triblespace::core::collection::records::CollectionHandle> {
    let signer = load_signer(pile, key)?;
    Ok(triblespace::core::blob::IntoBlob::<
        triblespace::core::blob::encodings::simplearchive::SimpleArchive,
    >::to_blob(descriptor(signer.verifying_key()).facts().clone())
    .get_handle())
}

/// One pile-resident executable carried by a standing intention.
///
/// The handle is the content hash, so it is simultaneously the pile address,
/// the identity recorded in the habit's own facts, and the local cache key.
/// Editing the script therefore yields a different habit at a different cache
/// path: no stale copy is reachable, because nothing is ever overwritten.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Script {
    pub handle: ScriptHandle,
    pub bytes: Vec<u8>,
}

/// Content hash a script will be addressed by, computed without publishing it.
///
/// Authoring surfaces need to name the attachment before the collection has
/// been written, and the address is a pure function of the bytes.
pub fn script_digest(bytes: &[u8]) -> String {
    let mut fragment = Fragment::empty();
    let handle = fragment.put::<blobencodings::RawBytes, _>(bytes.to_vec());
    hex::encode(handle.raw)
}

impl Script {
    /// Lowercase hex content hash — the cache key and the display form.
    pub fn digest(&self) -> String {
        hex::encode(self.handle.raw)
    }

    /// First eight hex digits, for one-line listings.
    pub fn short_digest(&self) -> String {
        self.digest()[..8].to_owned()
    }

    fn validate_identity(&self) -> std::result::Result<(), String> {
        let expected = self.digest();
        let actual = script_digest(&self.bytes);
        if actual != expected {
            return Err(format!(
                "Habit script handle {expected} does not address its carried bytes (actual {actual})"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Habit {
    pub id: Id,
    /// Display name. Deliberately **not** an identity: several definitions may
    /// carry the same label, and none of them owns it.
    pub label: String,
    /// Author-written source (`every …`, `daily at …`, or `when …`).
    pub condition: String,
    pub nudge: String,
    /// Executable the definition carries, when the condition names `@script`.
    pub script: Option<Script>,
    /// Definitions this one replaces, by intrinsic id.
    pub supersedes: Vec<Id>,
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

    /// Every definition displaying this name, case-insensitively.
    ///
    /// Several results are ordinary, not a conflict: the label is a display
    /// attribute and nothing owns it. Callers that need one definition must
    /// disambiguate by id rather than choose.
    pub fn labelled(&self, label: &str) -> Vec<&Habit> {
        let label = label.trim().to_ascii_lowercase();
        self.habits
            .values()
            .filter(|habit| habit.label.to_ascii_lowercase() == label)
            .collect()
    }

    /// Definitions no other definition supersedes — the current revisions.
    ///
    /// Liveness is a property of the supersession DAG and therefore of ids
    /// alone. It is never derived from the label: a name-based rule is not
    /// monotonic, because which definition "owns" a name depends on which
    /// facts a window happens to have observed, so two windows could disagree
    /// indefinitely while each is locally correct. An explicit edge only ever
    /// retires, never resurrects, so every window that has seen it agrees and
    /// order does not matter.
    pub fn live(&self) -> Vec<&Habit> {
        let superseded: BTreeSet<Id> = self
            .habits
            .values()
            .flat_map(|habit| habit.supersedes.iter().copied())
            .collect();
        self.habits
            .values()
            .filter(|habit| !superseded.contains(&habit.id))
            .collect()
    }

    /// Whether any other definition supersedes this one.
    pub fn is_superseded(&self, id: Id) -> bool {
        self.habits
            .values()
            .any(|habit| habit.supersedes.contains(&id))
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

    /// One row per **live** definition. A superseded revision keeps its facts
    /// as durable history but is no longer a standing intention, so it is not
    /// evaluated and cannot come due.
    pub fn rows(&self) -> Result<Vec<HabitRow>> {
        let mut rows = Vec::with_capacity(self.habits.len());
        for habit in self.live() {
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
                script: habit.script.clone(),
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
    pub script: Option<Script>,
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

fn habit_record(
    label: &str,
    condition: TextHandle,
    nudge: TextHandle,
    script: Option<ScriptHandle>,
    supersedes: &[Id],
) -> Fragment {
    entity! { _ @
        metadata::tag: &KIND_HABIT_ID,
        attrs::label: label,
        attrs::condition: condition,
        attrs::nudge: nudge,
        attrs::script?: script,
        metadata::supersedes*: supersedes.iter(),
    }
}

/// A condition and its attachment must agree in both directions.
///
/// Either mismatch describes a habit that cannot do what it says: a `@script`
/// with nothing to run, or an executable no condition will ever reach. Both are
/// caught where the definition is built, not where it silently stops firing.
fn check_script_agreement(condition: &Condition, has_script: bool, subject: &str) -> Result<()> {
    match (condition.uses_script(), has_script) {
        (true, false) => bail!(
            "{subject} condition names `{SCRIPT_TOKEN}` but carries no script; \
             attach one with `--script <path>`"
        ),
        (false, true) => bail!(
            "{subject} carries a script no condition reaches; \
             write the condition as `when {SCRIPT_TOKEN} <args>`"
        ),
        _ => Ok(()),
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
///
/// When `script` is present its bytes travel inside the fragment, exactly as
/// the condition and nudge payloads do. That is what makes the definition
/// self-contained: whoever receives this one collection commit receives the
/// executable too, and does not have to already hold some other collection —
/// or some machine-local path — for the intention to mean anything.
///
/// `supersedes` names the definitions this one replaces, by intrinsic id. The
/// edge is part of the record, so two windows authoring the same revision of
/// the same intention produce byte-identical facts and therefore the same id:
/// they converge on one definition instead of forking. Concurrent authoring
/// *without* an edge is not an error — it is two live definitions that happen
/// to share a display name, which is the truth, and a later revision citing
/// both resolves it.
pub fn habit_fragment(
    label: impl Into<String>,
    condition: impl Into<String>,
    nudge: impl Into<String>,
    script: Option<Vec<u8>>,
    supersedes: &[Id],
) -> Result<(Fragment, Id)> {
    let label = canonical_label(label)?;
    let condition = canonical_required(condition, "Habit condition")?;
    let parsed = Condition::parse(&condition).map_err(|error| anyhow!(error))?;
    let nudge = canonical_required(nudge, "Habit nudge")?;
    if let Some(bytes) = &script {
        if bytes.is_empty() {
            bail!("Habit script is empty");
        }
    }
    check_script_agreement(&parsed, script.is_some(), &format!("Habit {label:?}"))?;

    let supersedes = sorted_ids(supersedes.iter().copied());
    let mut fragment = Fragment::empty();
    let condition = fragment.put(condition);
    let nudge = fragment.put(nudge);
    let script = script.map(|bytes| fragment.put::<blobencodings::RawBytes, _>(bytes));
    let record = habit_record(&label, condition, nudge, script, &supersedes);
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

fn at_most_one<T>(values: Vec<T>, entity: Id, field: &str) -> Result<Option<T>> {
    if values.len() > 1 {
        bail!(
            "Habit entity {entity:x} has {} values for {field}; expected at most one",
            values.len()
        );
    }
    Ok(values.into_iter().next())
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
    script: Option<ScriptHandle>,
    supersedes: Vec<Id>,
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
        script: at_most_one(
            find!(value: ScriptHandle, pattern!(facts, [{ id @ attrs::script: ?value }])).collect(),
            id,
            "habit::script",
        )?,
        supersedes: sorted_ids(find!(
            value: Id,
            pattern!(facts, [{ id @ metadata::supersedes: ?value }])
        )),
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
        let expected = habit_record(
            &raw.label,
            raw.condition,
            raw.nudge,
            raw.script,
            &raw.supersedes,
        );
        if expected.root() != Some(id) {
            // Additive cutovers retain the exact random-id legacy record next
            // to its intrinsic native shadow. It remains durable evidence but
            // is not part of the live Habit view.
            continue;
        }
        ensure_exact_entity(facts, id, expected.facts(), "Habit definition")?;
        habits.insert(id, raw);
    }

    // The revision track is deliberately *not* gated here, unlike the state
    // track. Every rule one could impose on it — predecessors must be present,
    // must form an antichain, must not cycle — is a rule a partial view can
    // violate, and violating it would make the whole catalog unreadable to a
    // window that happened to receive the successor before what it retires.
    // Liveness is instead computed structurally in `Catalog::live`, where an
    // edge naming an unseen definition simply retires nothing yet, and retires
    // it the moment it arrives. Ids are intrinsic, so an id names one
    // definition forever and retiring it early is correct rather than
    // accidental. Adding facts can only ever retire more, never resurrect.

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

fn load_text(reader: &PileSnapshot, handle: TextHandle, field: &str) -> Result<String> {
    let value: View<str> = reader
        .get(handle)
        .with_context(|| format!("read Habit {field} payload {}", hex::encode(handle.raw)))?;
    Ok(value.to_string())
}

fn load_text_overlay<Overlay>(
    reader: &PileSnapshot,
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

/// Resolve a carried script, from the staged fragment first and the pile
/// second.
///
/// An unresolvable handle is a hard error naming both the habit and the exact
/// missing blob. It is deliberately not degraded into "this habit is not due":
/// a standing intention that quietly stops firing is worse than one that
/// refuses to be read at all, because nobody notices the first.
fn load_script_overlay<Overlay>(
    reader: &PileSnapshot,
    overlay: Option<&Overlay>,
    handle: ScriptHandle,
    habit: Id,
) -> Result<Script>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    let missing = || {
        anyhow!(
            "Habit {habit:x} script blob {} is not in this pile",
            hex::encode(handle.raw)
        )
    };
    if let Some(overlay) = overlay {
        if overlay
            .metadata(handle)
            .expect("in-memory Habit attachment lookup is infallible")
            .is_some()
        {
            let bytes: anybytes::Bytes = overlay.get(handle).map_err(|_| missing())?;
            return Ok(Script {
                handle,
                bytes: bytes.to_vec(),
            });
        }
    }
    let bytes: anybytes::Bytes = reader.get(handle).map_err(|_| missing())?;
    Ok(Script {
        handle,
        bytes: bytes.to_vec(),
    })
}

fn decode_catalog<Overlay>(
    reader: &PileSnapshot,
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
        let parsed = Condition::parse(&condition)
            .map_err(|error| anyhow!("Habit {} condition: {error}", raw_habit.id))?;

        let script = match raw_habit.script {
            Some(handle) => Some(load_script_overlay(reader, overlay, handle, raw_habit.id)?),
            None => None,
        };
        check_script_agreement(
            &parsed,
            script.is_some(),
            &format!("Habit {:x}", raw_habit.id),
        )?;

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
                script,
                supersedes: raw_habit.supersedes.clone(),
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
pub fn load_catalog(reader: &PileSnapshot, facts: &TribleSet) -> Result<Catalog> {
    let raw = validate_structure(facts)?;
    decode_catalog(reader, None::<&PileSnapshot>, raw)
}

pub fn validate_catalog(reader: &PileSnapshot, facts: &TribleSet) -> Result<()> {
    load_catalog(reader, facts).map(drop)
}

/// Preflight the exact set union a publication would create, resolving blob
/// handles from the staged complete fragment before it is appended.
pub fn validate_catalog_union(
    reader: &PileSnapshot,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<TribleSet> {
    let mut union = current.clone();
    union += fragment.facts().clone();
    let raw = validate_structure(&union)?;
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .snapshot()
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
        if raw.supersedes.contains(&id) {
            bail!("Habit {id:x} supersedes itself");
        }
        let expected = ensure_intrinsic(
            id,
            habit_record(
                &raw.label,
                raw.condition,
                raw.nudge,
                raw.script,
                &raw.supersedes,
            ),
            "Habit definition",
        )?;
        let mut local = fragment.clone();
        let reader = local
            .blobs_mut()
            .snapshot()
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
        let parsed = Condition::parse(&condition).map_err(|error| anyhow!(error))?;
        if let Some(handle) = raw.script {
            let script: anybytes::Bytes = reader.get(handle).map_err(|_| {
                anyhow!(
                    "complete Habit definition {id:x} is missing script payload {}",
                    hex::encode(handle.raw)
                )
            })?;
            if script.is_empty() {
                bail!("Habit {id:x} script payload is empty");
            }
        }
        check_script_agreement(&parsed, raw.script.is_some(), &format!("Habit {id:x}"))?;
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
    let mut pile = open_pile_strict(pile_path)?;
    let collection = open_scope(&mut pile, DEFAULT_SCOPE_ID, &signer)?;
    let result = (|| {
        let store_snapshot = pile
            .snapshot()
            .context("freeze native Habit store snapshot")?;
        let (facts, _) = crate::storage::read_fact_collection(collection, &store_snapshot)
            .context("read native Habit collection")?;
        validate_catalog_union(&store_snapshot, &facts, &fragment)
            .context("preflight complete Habit publication")?;
        drop(store_snapshot);
        pile.commit(collection, &signer, fragment)
            .context("commit complete Habit record")
    })();
    finish_pile(pile, result)
}

/// Materialize the fixed collection through its durable signer and return the
/// strict decoded set value.
pub fn read_catalog(pile_path: &Path, key_path: Option<&Path>) -> Result<Catalog> {
    let signer = load_signer(pile_path, key_path)?;
    let mut pile = open_pile_strict(pile_path)?;
    let collection = open_scope(&mut pile, DEFAULT_SCOPE_ID, &signer)?;
    let result = (|| {
        let store_snapshot = pile
            .snapshot()
            .context("freeze native Habit store snapshot")?;
        let (facts, _) = crate::storage::read_fact_collection(collection, &store_snapshot)
            .context("read native Habit collection")?;
        load_catalog(&store_snapshot, &facts).context("validate native Habit catalog")
    })();
    finish_pile(pile, result)
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

/// Local cache root holding materialized habit scripts.
///
/// Content-addressed, so nothing in it is ever invalidated — only added to. The
/// override exists for sandboxes with a read-only home, and for tests.
pub fn script_cache_dir() -> std::result::Result<std::path::PathBuf, String> {
    if let Some(dir) = std::env::var_os("FACULTIES_HABIT_SCRIPT_CACHE") {
        return Ok(std::path::PathBuf::from(dir));
    }
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cache"))
        })
        .ok_or_else(|| {
            "neither FACULTIES_HABIT_SCRIPT_CACHE, XDG_CACHE_HOME nor HOME is set, so there is \
             nowhere to materialize the habit script"
                .to_owned()
        })?;
    Ok(base.join("faculties").join("habit"))
}

/// Whether the cache already holds this exact script, executable.
///
/// The path is the content hash and files arrive there only by rename, but the
/// cache is still ordinary user-writable state. Check the bytes as well as the
/// length and mode so a same-length edit can never run under somebody else's
/// digest.
fn cached_copy_is_usable(path: &Path, script: &Script) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => {
            meta.is_file()
                && meta.len() == script.bytes.len() as u64
                && meta.permissions().mode() & 0o100 != 0
                && std::fs::read(path)
                    .map(|bytes| bytes == script.bytes)
                    .unwrap_or(false)
        }
        Err(_) => false,
    }
}

/// Write a carried script into the content-addressed cache and return its path.
///
/// Staging plus rename is what makes the cache safe to trust: the hash-named
/// path only ever appears complete, so a crashed writer cannot leave a
/// truncated executable behind for the next evaluation to run.
pub fn materialize_script(script: &Script) -> std::result::Result<std::path::PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;

    script.validate_identity()?;
    let directory = script_cache_dir()?;
    let path = directory.join(script.digest());
    if cached_copy_is_usable(&path, script) {
        return Ok(path);
    }
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("create habit script cache {}: {error}", directory.display()))?;
    // The staging name is unique per *attempt*, not per process: two
    // evaluations of the same script inside one process would otherwise share
    // a staging path and rename it out from under each other.
    static ATTEMPT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let attempt = ATTEMPT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let staging = directory.join(format!(
        ".{}.{}.{attempt}.staging",
        script.digest(),
        std::process::id()
    ));
    std::fs::write(&staging, &script.bytes)
        .map_err(|error| format!("write habit script {}: {error}", staging.display()))?;
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).map_err(
        |error| {
            let _ = std::fs::remove_file(&staging);
            format!(
                "make habit script {} executable: {error}",
                staging.display()
            )
        },
    )?;
    std::fs::rename(&staging, &path).map_err(|error| {
        let _ = std::fs::remove_file(&staging);
        format!("install habit script {}: {error}", path.display())
    })?;
    Ok(path)
}

/// Quote one path as a single shell word.
///
/// The cache path is generated, but its root comes from the environment, so
/// quoting is not optional.
fn shell_word(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', r"'\''"))
}

/// Resolve a parsed condition into the exact shell command to run.
///
/// A leading `@script` command word is rewritten to the local path of the
/// materialized blob; everything else passes through untouched.
pub fn resolve_command(
    condition: &Condition,
    script: Option<&Script>,
) -> std::result::Result<String, String> {
    let Some(suffix) = condition.script_suffix() else {
        return Ok(condition.command.clone());
    };
    let script = script.ok_or_else(|| {
        format!("condition names `{SCRIPT_TOKEN}` but this Habit carries no script")
    })?;
    let path = materialize_script(script)?;
    Ok(format!("{}{suffix}", shell_word(&path)))
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
    match output.status.code() {
        Some(0) => Ok(true),
        Some(code @ (126 | 127)) => {
            let detail = String::from_utf8_lossy(&output.stderr);
            let detail = detail.trim();
            Err(if detail.is_empty() {
                format!("condition command exited {code}")
            } else {
                format!("condition command exited {code}: {detail}")
            })
        }
        Some(_) => Ok(false),
        None => Err(format!(
            "condition command terminated by signal: {command:?}"
        )),
    }
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
    // A predicate that cannot be resolved is an error, never a quiet "not
    // due" — the whole point of carrying the script is that this cannot
    // depend on which machine is asking.
    let command = match resolve_command(&condition, row.script.as_ref()) {
        Ok(command) => command,
        Err(error) => return State::Failed(error),
    };
    match condition_holds(&command, at) {
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

    use crate::storage::load_signer;
    use crate::test_support::initialize_open_collection_fixture;

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
            initialize_open_collection_fixture(&pile, Some(&key));
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

    fn live_ids(catalog: &Catalog) -> Vec<Id> {
        catalog.live().into_iter().map(|habit| habit.id).collect()
    }

    fn row(condition: &str, completed_at: &[i64], activation: Activation) -> HabitRow {
        HabitRow {
            id: Id::new([1; 16]).unwrap(),
            label: "test".to_owned(),
            condition: condition.to_owned(),
            nudge: "do it".to_owned(),
            script: None,
            activation,
            completed_at: completed_at.to_vec(),
        }
    }

    /// One content-addressed cache for the whole test binary.
    ///
    /// The cache root is process-global state, so tests share it rather than
    /// racing to set it; content addressing makes sharing safe.
    fn shared_cache() -> &'static Path {
        static CACHE: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
        let directory = CACHE.get_or_init(|| {
            let directory = tempfile::tempdir().unwrap();
            std::env::set_var("FACULTIES_HABIT_SCRIPT_CACHE", directory.path());
            directory
        });
        directory.path()
    }

    /// A carried script, addressed exactly as publication would address it.
    fn script(source: &str) -> Script {
        let mut fragment = Fragment::empty();
        let handle = fragment.put::<blobencodings::RawBytes, _>(source.as_bytes().to_vec());
        let script = Script {
            handle,
            bytes: source.as_bytes().to_vec(),
        };
        // The pre-publication digest an authoring surface prints must be the
        // address the published definition actually carries.
        assert_eq!(script_digest(source.as_bytes()), script.digest());
        script
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
        let (fragment, id) =
            habit_fragment("journal", "every 1d", "write the journal", None, &[]).unwrap();
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
        let team = signer.verifying_key();
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        let collection = open_scope(&mut pile, DEFAULT_SCOPE_ID, &signer).unwrap();
        assert_eq!(collection, pile.collection(descriptor(team)).unwrap());
        pile.close().unwrap();
    }

    #[test]
    fn concurrent_state_assertions_stay_forked_until_reconciled() {
        let fixture = Fixture::new();
        let (definition, habit) =
            habit_fragment("journal", "every 1h", "write", None, &[]).unwrap();
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

    /// Revision is an explicit id edge, so the upgrade path exists without the
    /// label ever behaving like a key.
    #[test]
    fn a_successor_retires_its_predecessor_by_id_not_by_name() {
        let fixture = Fixture::new();
        let (original, original_id) = habit_fragment(
            "sweep",
            "when /usr/local/bin/sweep --due",
            "sweep",
            None,
            &[],
        )
        .unwrap();
        fixture.publish(original);
        assert_eq!(live_ids(&fixture.catalog()), vec![original_id]);

        let (successor, successor_id) = habit_fragment(
            "sweep",
            "when @script --due",
            "sweep",
            Some(b"#!/bin/sh\nexit 0\n".to_vec()),
            &[original_id],
        )
        .unwrap();
        fixture.publish(successor);

        let catalog = fixture.catalog();
        // Both definitions remain; only the successor is live, and only it is
        // evaluated.
        assert_eq!(catalog.habits().count(), 2);
        assert_eq!(catalog.labelled("sweep").len(), 2);
        assert_eq!(live_ids(&catalog), vec![successor_id]);
        assert!(catalog.is_superseded(original_id));
        assert_eq!(
            catalog
                .rows()
                .unwrap()
                .iter()
                .map(|row| row.id)
                .collect::<Vec<_>>(),
            [successor_id]
        );
    }

    /// Liveness must not depend on the order facts arrive in. Publishing the
    /// successor before its predecessor is legal set union, and both orders
    /// have to agree — this is the property a name-based rule cannot give.
    #[test]
    fn liveness_is_order_independent() {
        let (original, original_id) =
            habit_fragment("sweep", "every 1h", "sweep", None, &[]).unwrap();
        let (successor, successor_id) =
            habit_fragment("sweep", "every 2h", "sweep", None, &[original_id]).unwrap();

        for order in [[0usize, 1], [1, 0]] {
            let fixture = Fixture::new();
            for index in order {
                let fragment = if index == 0 {
                    original.clone()
                } else {
                    successor.clone()
                };
                fixture.publish(fragment);
            }
            assert_eq!(
                live_ids(&fixture.catalog()),
                vec![successor_id],
                "{order:?}"
            );
        }
    }

    /// Two windows authoring the same revision of the same intention converge
    /// on one definition, because identity is the content and not the name.
    #[test]
    fn identical_revisions_authored_independently_are_one_definition() {
        let fixture = Fixture::new();
        let (original, original_id) =
            habit_fragment("sweep", "every 1h", "sweep", None, &[]).unwrap();
        fixture.publish(original);

        let first = habit_fragment("sweep", "every 2h", "sweep", None, &[original_id]).unwrap();
        let second = habit_fragment("sweep", "every 2h", "sweep", None, &[original_id]).unwrap();
        assert_eq!(first.1, second.1);
        fixture.publish(first.0);
        fixture.publish(second.0);
        assert_eq!(fixture.catalog().habits().count(), 2);
        assert_eq!(live_ids(&fixture.catalog()), vec![first.1]);
    }

    /// Concurrent creation without an edge is two live definitions sharing a
    /// name. That is the truth, and it stays visible until an explicit edge
    /// resolves it — no winner is picked.
    #[test]
    fn concurrent_creation_stays_forked_until_an_edge_resolves_it() {
        let fixture = Fixture::new();
        let (mine, mine_id) = habit_fragment("sweep", "every 1h", "sweep", None, &[]).unwrap();
        let (theirs, theirs_id) = habit_fragment("sweep", "every 2h", "sweep", None, &[]).unwrap();
        fixture.publish(mine);
        fixture.publish(theirs);
        assert_eq!(live_ids(&fixture.catalog()).len(), 2);

        let (joined, joined_id) =
            habit_fragment("sweep", "every 3h", "sweep", None, &[mine_id, theirs_id]).unwrap();
        fixture.publish(joined);
        assert_eq!(live_ids(&fixture.catalog()), vec![joined_id]);
    }

    /// An edge naming a definition this window has not seen is legal and
    /// retires nothing yet. Rejecting it would mean a window that received the
    /// successor first could not read the catalog at all — the partial-view
    /// hazard that makes any such rule non-monotonic.
    #[test]
    fn an_edge_to_an_unseen_definition_retires_it_on_arrival() {
        let fixture = Fixture::new();
        let (original, original_id) =
            habit_fragment("sweep", "every 1h", "sweep", None, &[]).unwrap();
        let (successor, successor_id) =
            habit_fragment("sweep", "every 2h", "sweep", None, &[original_id]).unwrap();

        fixture.publish(successor);
        // The predecessor is not here; nothing is retired, and the catalog reads.
        assert_eq!(live_ids(&fixture.catalog()), vec![successor_id]);
        assert!(fixture.catalog().is_superseded(original_id));

        fixture.publish(original);
        // It arrives already retired, and liveness is unchanged.
        assert_eq!(fixture.catalog().habits().count(), 2);
        assert_eq!(live_ids(&fixture.catalog()), vec![successor_id]);
    }

    #[test]
    fn concurrent_definition_conflicts_are_visible_not_timestamp_arbitrated() {
        let fixture = Fixture::new();
        let (daily, daily_id) =
            habit_fragment("hygiene", "every 1d", "inspect branches", None, &[]).unwrap();
        let (weekly, weekly_id) =
            habit_fragment("hygiene", "every 7d", "inspect branches", None, &[]).unwrap();
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
        let mut fragment = habit_fragment("journal", "every 1h", "write", None, &[])
            .unwrap()
            .0;
        let id = fragment.root().unwrap();
        fragment += entity! { ExclusiveId::force_ref(&id) @ metadata::created_at: at(1.0) };
        assert!(validate_publication_fragment(&fragment).is_err());

        let dangling = completion_fragment(Id::new([9; 16]).unwrap(), at(1.0))
            .unwrap()
            .0;
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("empty.pile");
        File::create(&pile_path).unwrap();
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let reader = pile.snapshot().unwrap();
        let error = validate_catalog_union(&reader, &TribleSet::new(), &fragment).unwrap_err();
        assert!(format!("{error:#}").contains("expected exactly"));
        let error = validate_catalog_union(&reader, &TribleSet::new(), &dangling).unwrap_err();
        assert!(format!("{error:#}").contains("missing definition"));
        pile.close().unwrap();
    }

    #[test]
    fn additive_legacy_records_are_inert_beside_exact_intrinsic_shadows() {
        let (mut fragment, native) =
            habit_fragment("journal", "every 1h", "write", None, &[]).unwrap();
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
        let reader = pile.snapshot().unwrap();
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
        let bare = habit_record("journal", missing_condition, missing_nudge, None, &[]);
        let error = validate_publication_fragment(&bare).unwrap_err();
        assert!(format!("{error:#}").contains("missing condition payload"));
    }

    /// The point of the whole feature: the predicate is the pile's bytes, not
    /// anything the evaluating machine happens to have on disk or on PATH.
    #[test]
    fn a_carried_script_is_run_from_the_content_addressed_cache() {
        shared_cache();
        let due = script("#!/bin/sh\nexit 0\n");
        let mut row = row("when @script --due", &[], Activation::Active(Vec::new()));
        row.script = Some(due.clone());
        assert_eq!(evaluate(&row, 10_000, Path::new(".")), State::Due);

        let path = materialize_script(&due).unwrap();
        assert_eq!(path.parent().unwrap(), shared_cache());
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), due.digest());
        assert_eq!(std::fs::read(&path).unwrap(), due.bytes);

        let mut waiting = row.clone();
        waiting.script = Some(script("#!/bin/sh\nexit 1\n"));
        assert_eq!(evaluate(&waiting, 10_000, Path::new(".")), State::Waiting);
    }

    /// Editing a script changes its hash, so it lands beside the old copy
    /// rather than on top of it. Nothing can execute a superseded body.
    #[test]
    fn an_edited_script_is_a_different_cache_entry() {
        shared_cache();
        let first = script("#!/bin/sh\nexit 0\n");
        let second = script("#!/bin/sh\nexit 1\n");
        assert_ne!(first.digest(), second.digest());
        let first_path = materialize_script(&first).unwrap();
        let second_path = materialize_script(&second).unwrap();
        assert_ne!(first_path, second_path);
        assert_eq!(std::fs::read(&first_path).unwrap(), first.bytes);
        assert_eq!(std::fs::read(&second_path).unwrap(), second.bytes);
    }

    /// A truncated leftover at the hash path is repaired, not executed. Rename
    /// makes this unreachable in practice; the check is what makes that a fact
    /// rather than an assumption.
    #[test]
    fn a_short_cache_entry_is_rewritten_rather_than_trusted() {
        let cache = shared_cache();
        let full = script("#!/bin/sh\n# a longer body\nexit 0\n");
        let path = cache.join(full.digest());
        std::fs::write(&path, b"#!/bin/sh\n").unwrap();
        assert_eq!(materialize_script(&full).unwrap(), path);
        assert_eq!(std::fs::read(&path).unwrap(), full.bytes);
    }

    /// A hash-shaped path is not proof by itself: the cache is user-writable,
    /// so a same-length edit must be repaired before evaluation can execute it.
    #[test]
    fn a_same_length_cache_edit_is_rewritten_rather_than_executed() {
        shared_cache();
        let expected = script("#!/bin/sh\n# cache-integrity-only\nexit 0\n");
        let path = materialize_script(&expected).unwrap();
        let altered = b"#!/bin/sh\n# cache-integrity-only\nexit 1\n";
        assert_eq!(altered.len(), expected.bytes.len());
        std::fs::write(&path, altered).unwrap();

        assert_eq!(materialize_script(&expected).unwrap(), path);
        assert_eq!(std::fs::read(path).unwrap(), expected.bytes);
    }

    #[test]
    fn a_script_handle_cannot_name_different_bytes() {
        shared_cache();
        let named = script("#!/bin/sh\n# named body\nexit 0\n");
        let other = script("#!/bin/sh\n# other body\nexit 0\n");
        let forged = Script {
            handle: named.handle,
            bytes: other.bytes,
        };
        let error = materialize_script(&forged).unwrap_err();
        assert!(
            error.contains("does not address its carried bytes"),
            "{error}"
        );
    }

    /// Substitution has to survive a cache root with a quote or a space in it,
    /// because the root comes from the environment.
    #[test]
    fn script_substitution_produces_one_shell_word() {
        let directory = tempfile::tempdir().unwrap();
        let awkward = directory.path().join("it's a cache");
        std::fs::create_dir_all(&awkward).unwrap();
        let path = awkward.join("body");
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
        let command = format!("test -f {} && exit 0", shell_word(&path));
        assert!(condition_holds(&command, Path::new(".")).unwrap());
    }

    #[test]
    fn script_substitution_only_replaces_the_leading_command_word() {
        shared_cache();
        let carried = script("#!/bin/sh\nexit 0\n");
        let condition = Condition::parse("when @scripture @script").unwrap();
        assert_eq!(
            resolve_command(&condition, Some(&carried)).unwrap(),
            "@scripture @script"
        );
    }

    #[test]
    fn unavailable_shell_commands_are_errors_not_false_predicates() {
        assert!(condition_holds("exit 126", Path::new(".")).is_err());
        assert!(condition_holds("exit 127", Path::new(".")).is_err());
        assert_eq!(condition_holds("exit 1", Path::new(".")).unwrap(), false);
    }

    /// Round-trip: publish a definition carrying its script, read it back from
    /// the pile alone, and get the same bytes and the same handle.
    #[test]
    fn a_published_definition_carries_its_script_through_the_pile() {
        let fixture = Fixture::new();
        let source = b"#!/bin/sh\nexit 0\n".to_vec();
        let (fragment, id) = habit_fragment(
            "sweep",
            "when @script --due",
            "sweep the worktrees",
            Some(source.clone()),
            &[],
        )
        .unwrap();
        fixture.publish(fragment);
        let catalog = fixture.catalog();
        let carried = catalog.habit(id).unwrap().script.as_ref().unwrap();
        assert_eq!(carried.bytes, source);
        assert_eq!(carried.digest().len(), 64);
    }

    /// A definition and its attachment must agree in both directions, and the
    /// check has to hold at publication as well as at authoring.
    #[test]
    fn condition_and_attachment_must_agree() {
        let dangling =
            habit_fragment("sweep", "when @script --due", "sweep", None, &[]).unwrap_err();
        assert!(format!("{dangling:#}").contains("carries no script"));

        let unreachable = habit_fragment(
            "sweep",
            "every 1h",
            "sweep",
            Some(b"#!/bin/sh\n".to_vec()),
            &[],
        )
        .unwrap_err();
        assert!(format!("{unreachable:#}").contains("no condition reaches"));

        let mut fragment = Fragment::empty();
        let condition = fragment.put("when @script --due".to_owned());
        let nudge = fragment.put("sweep".to_owned());
        let record = habit_record("sweep", condition, nudge, None, &[]);
        fragment += record;
        let error = validate_publication_fragment(&fragment).unwrap_err();
        assert!(format!("{error:#}").contains("carries no script"));
    }

    /// An unresolvable script names the habit and the exact missing blob, and
    /// refuses; it never degrades into a habit that silently stops firing.
    #[test]
    fn an_unresolvable_script_blob_is_a_loud_error() {
        let mut fragment = Fragment::empty();
        let condition = fragment.put("when @script --due".to_owned());
        let nudge = fragment.put("sweep".to_owned());
        let absent = ScriptHandle::new([7; 32]);
        let record = habit_record("sweep", condition, nudge, Some(absent), &[]);
        let id = record.root().unwrap();
        fragment += record;

        let error = validate_publication_fragment(&fragment).unwrap_err();
        assert!(format!("{error:#}").contains("missing script payload"));
        assert!(format!("{error:#}").contains(&hex::encode(absent.raw)));

        // And the same handle, reached through a pile which does not hold it.
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("empty.pile");
        File::create(&pile_path).unwrap();
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let reader = pile.snapshot().unwrap();
        let error = validate_catalog_union(&reader, &TribleSet::new(), &fragment).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains(&format!("{id:x}")), "{rendered}");
        assert!(rendered.contains("is not in this pile"), "{rendered}");
        pile.close().unwrap();
    }
}
