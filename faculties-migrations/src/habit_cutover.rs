//! Exact stopped-world projection of the legacy `habit` branch.
//!
//! The legacy faculty went through two durable schemas. Its first, push-based
//! writer stored the condition inline, attached sender/recipient addresses,
//! and used `KIND_DONE_ID` for automatic *fire* events. The later pull-based
//! writer stored the condition as a blob, removed those addresses, and reused
//! the same event kind for explicit *done* events. The signed legacy commit
//! description is the only durable discriminator between those otherwise
//! identical event records (`habit fires` versus `habit event`), so an absent
//! or unfamiliar description is rejected rather than guessed.
//!
//! Every authored legacy content fragment is republished fact-exact, with its
//! signed description, timestamp, and attached semantic metadata projected
//! onto the new commit. Native intrinsic shadows live in one separate
//! normalization fragment: this keeps machine-derived state out of
//! human-authored provenance and makes every publication prefix before the
//! final fragment a valid empty native Habit view. Push-era fires remain inert
//! provenance; treating delivery as human completion would recreate the
//! semantic bug that motivated the pull model.
//!
//! Legacy pause/resume used whole-second latest-wins arbitration. The transform
//! turns each habit's timestamp strata into a predecessor DAG. Events in one
//! second which agree become concurrent same-state heads; a later stratum
//! cites every prior head. Conflicting states in the same second had no stable
//! legacy winner and therefore fail the migration.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{self, BlobStoreGet};
use triblespace::macros::{attributes, find, pattern};
use triblespace::prelude::*;

use crate::collection_cutover::{project_legacy_authored_commits, FrozenLegacyBranch, FrozenSource, LegacyCommitCoordinate, LegacyPinCoordinate};
use faculties::storage::{publish_fragments};
use faculties::habits::{self, DeclaredState, IntervalValue, TextHandle};
use faculties::schemas::habit::{
    attrs, Condition, DEFAULT_SCOPE_ID, KIND_DONE_ID, KIND_HABIT_ID, KIND_STATE_ID,
    MAX_LABEL_BYTES, STATE_ACTIVE, STATE_PAUSED,
};

pub use faculties::schemas::habit::LEGACY_BRANCH_NAME;

const LEGACY_HABIT_LABEL: &str = "habit";
const LEGACY_FIRE_LABEL: &str = "habit_fire";
const LEGACY_DONE_LABEL: &str = "habit_done";
const LEGACY_STATE_LABEL: &str = "habit_state";
const LEGACY_FIRE_COMMIT_MESSAGE: &str = "habit fires";
const LEGACY_EVENT_COMMIT_MESSAGE: &str = "habit event";

/// Published attributes from the initial push-based writer.
///
/// `condition` deliberately shares its byte identity with the later Handle
/// attribute but retains the historical ShortString interpretation here.
mod push_attrs {
    use super::*;

    attributes! {
        "134ECC925E8547B46AF67D6DC29B5F5C" unsafe as condition:
            inlineencodings::ShortString;
        "3FF549A7BF885151D06582AC9BCF2A8B" unsafe as recipient:
            inlineencodings::GenId;
        "4991F6A9D3F53F427A074E6272C0C6DA" unsafe as sender:
            inlineencodings::GenId;
    }
}

/// One exact authored commit conserved from the legacy branch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HabitMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
}

/// Conservation and semantic-projection summary.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HabitMigrationReport {
    pub authored_commits: usize,
    pub preserved_facts: usize,
    pub push_definitions: usize,
    pub pull_definitions: usize,
    pub legacy_fires: usize,
    pub legacy_completions: usize,
    pub legacy_state_events: usize,
    pub canonical_definitions: usize,
    pub canonical_completions: usize,
    pub canonical_state_assertions: usize,
    pub canonical_facts: usize,
    pub output_facts: usize,
}

/// Pure stopped-world plan ready for native collection publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HabitMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<HabitMigrationCommit>,
    normalization: Fragment,
    original: TribleSet,
    canonical: TribleSet,
    report: HabitMigrationReport,
}

impl HabitMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[HabitMigrationCommit] {
        &self.commits
    }

    /// Machine-derived intrinsic shadows, deliberately separate from every
    /// exact authored fragment.
    pub fn normalization(&self) -> &Fragment {
        &self.normalization
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    pub fn canonical_facts(&self) -> &TribleSet {
        &self.canonical
    }

    pub const fn report(&self) -> &HabitMigrationReport {
        &self.report
    }

    pub fn materialized_facts(&self) -> TribleSet {
        let mut facts = TribleSet::new();
        for commit in &self.commits {
            facts += commit.fragment.facts().clone();
        }
        facts += self.normalization.facts().clone();
        facts
    }

    pub fn publication_fragments(&self) -> Vec<Fragment> {
        let mut fragments: Vec<_> = self
            .commits
            .iter()
            .map(|commit| commit.fragment.clone())
            .collect();
        if !self.normalization.facts().is_empty() {
            fragments.push(self.normalization.clone());
        }
        fragments
    }

    pub fn verify_conservation(&self) -> Result<()> {
        let mut expected = self.original.clone();
        expected += self.canonical.clone();
        if self.materialized_facts() != expected {
            bail!("planned Habit collection is not original facts union canonical shadows");
        }
        Ok(())
    }

    fn validate(&self, reader: &PileReader) -> Result<()> {
        self.verify_conservation()?;
        let complete = self.publication_fragments().into_iter().fold(
            Fragment::empty(),
            |mut complete, fragment| {
                complete += fragment;
                complete
            },
        );
        let validated = habits::validate_catalog_union(reader, &TribleSet::new(), &complete)
            .context("validate planned Habit collection and attachments")?;
        if validated != self.materialized_facts() {
            bail!("planned Habit fragment union changed during validation");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DefinitionEra {
    Push,
    Pull,
}

#[derive(Clone, Debug)]
struct LegacyDefinition {
    id: Id,
    era: DefinitionEra,
    label: String,
    condition: String,
    nudge: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletionMeaning {
    Fire,
    Done,
}

#[derive(Clone, Debug)]
struct LegacyCompletion {
    id: Id,
    habit: Id,
    at: IntervalValue,
    meaning: CompletionMeaning,
}

#[derive(Clone, Debug)]
struct LegacyState {
    id: Id,
    habit: Id,
    state: DeclaredState,
    at: IntervalValue,
    second: i64,
}

#[derive(Clone, Debug, Default)]
struct LegacyCatalog {
    definitions: BTreeMap<Id, LegacyDefinition>,
    completions: BTreeMap<Id, LegacyCompletion>,
    states: BTreeMap<Id, LegacyState>,
}

/// Plan the complete named legacy Habit branch without mutating its pile.
pub fn plan(source: &FrozenSource) -> Result<HabitMigrationPlan> {
    let branch = source
        .legacy_branch(LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Habit branch"))?;
    let commit_messages = legacy_commit_messages(source, &branch)?;
    let projected = project_legacy_authored_commits(source, &branch, validate_legacy_payloads)
        .context("project frozen Habit authored commits")?;

    let source_pin = branch.pin_coordinate();
    let mut original = TribleSet::new();
    let mut owners = BTreeMap::<Id, BTreeSet<LegacyCommitCoordinate>>::new();
    for commit in &projected {
        if commit.source.branch != source_pin.id || commit.source.pin != source_pin.value {
            bail!("Habit authored commits do not belong to one frozen branch pin");
        }
        original += commit.content.facts().clone();
        for fact in commit.content.facts() {
            owners.entry(*fact.e()).or_default().insert(commit.source);
        }
    }

    let legacy = validate_legacy_catalog(source.reader(), &original, &owners, &commit_messages)?;

    let mut records = BTreeMap::<Id, Fragment>::new();
    let mut definition_ids = BTreeMap::<Id, Id>::new();
    let mut push_definitions = 0usize;
    let mut pull_definitions = 0usize;
    for definition in legacy.definitions.values() {
        match definition.era {
            DefinitionEra::Push => push_definitions += 1,
            DefinitionEra::Pull => pull_definitions += 1,
        }
        let (record, native) = habits::habit_fragment(
            definition.label.clone(),
            definition.condition.clone(),
            definition.nudge.clone(),
            None,
            &[],
        )?;
        insert_canonical(&mut records, record)?;
        definition_ids.insert(definition.id, native);
    }

    let mut canonical_completions = 0usize;
    let mut legacy_fires = 0usize;
    let mut legacy_completions = 0usize;
    for completion in legacy.completions.values() {
        match completion.meaning {
            CompletionMeaning::Fire => {
                legacy_fires += 1;
            }
            CompletionMeaning::Done => {
                legacy_completions += 1;
                let habit = definition_ids[&completion.habit];
                let (record, _) = habits::completion_fragment(habit, completion.at)?;
                if insert_canonical(&mut records, record)? {
                    canonical_completions += 1;
                }
            }
        }
    }

    let mut canonical_state_assertions = 0usize;
    let mut states_by_habit = BTreeMap::<Id, Vec<&LegacyState>>::new();
    for state in legacy.states.values() {
        states_by_habit.entry(state.habit).or_default().push(state);
    }
    for (legacy_habit, states) in states_by_habit {
        let native_habit = definition_ids[&legacy_habit];
        let mut strata = BTreeMap::<i64, Vec<&LegacyState>>::new();
        for state in states {
            strata.entry(state.second).or_default().push(state);
        }
        let mut frontier = Vec::<Id>::new();
        for (second, mut stratum) in strata {
            let meanings: BTreeSet<_> = stratum.iter().map(|state| state.state).collect();
            if meanings.len() != 1 {
                let ids = stratum
                    .iter()
                    .map(|state| format!("{:X}", state.id))
                    .collect::<Vec<_>>()
                    .join(", ");
                bail!(
                    "legacy Habit {legacy_habit:X} has conflicting state events in arbitration second {second}: {ids}"
                );
            }
            stratum.sort_unstable_by_key(|state| (state.at, state.id));
            let mut next = Vec::new();
            for state in stratum {
                let (record, id) =
                    habits::state_fragment(native_habit, state.state, &frontier, state.at)?;
                if insert_canonical(&mut records, record)? {
                    canonical_state_assertions += 1;
                }
                next.push(id);
            }
            next.sort_unstable();
            next.dedup();
            frontier = next;
        }
    }

    let canonical_definitions = definition_ids
        .values()
        .copied()
        .collect::<BTreeSet<_>>()
        .len();
    let mut normalization = Fragment::empty();
    for (_, record) in records {
        normalization += record;
    }
    let canonical = normalization.facts().clone();

    let commits: Vec<_> = projected
        .into_iter()
        .map(|projected| {
            let mut fragment = projected.content;
            fragment.describe_with(projected.metadata);
            HabitMigrationCommit {
                source: projected.source,
                fragment,
            }
        })
        .collect();

    let mut output = original.clone();
    output += canonical.clone();
    let plan = HabitMigrationPlan {
        source_pin,
        report: HabitMigrationReport {
            authored_commits: commits.len(),
            preserved_facts: original.len(),
            push_definitions,
            pull_definitions,
            legacy_fires,
            legacy_completions,
            legacy_state_events: legacy.states.len(),
            canonical_definitions,
            canonical_completions,
            canonical_state_assertions,
            canonical_facts: canonical.len(),
            output_facts: output.len(),
        },
        commits,
        normalization,
        original,
        canonical,
    };
    plan.validate(source.reader())?;
    Ok(plan)
}

/// Publish a verified plan through the native collection facade.
///
/// Every legacy Habit writer must remain stopped from [`FrozenSource`]
/// creation through publication. Replay is exact and idempotent.
pub fn publish(
    source: &FrozenSource,
    plan: &HabitMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Habit migration plan does not belong to this frozen source");
    }
    plan.validate(source.reader())?;
    publish_fragments(target, key, DEFAULT_SCOPE_ID, plan.publication_fragments())
}

fn insert_canonical(records: &mut BTreeMap<Id, Fragment>, record: Fragment) -> Result<bool> {
    let id = record
        .root()
        .ok_or_else(|| anyhow!("canonical Habit shadow has no unique intrinsic root"))?;
    match records.entry(id) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(record);
            Ok(true)
        }
        std::collections::btree_map::Entry::Occupied(entry) => {
            if entry.get().facts() != record.facts() {
                bail!("intrinsic Habit id collision at {id:X}");
            }
            Ok(false)
        }
    }
}

fn legacy_commit_messages(
    source: &FrozenSource,
    branch: &FrozenLegacyBranch,
) -> Result<BTreeMap<LegacyCommitCoordinate, Option<String>>> {
    let mut messages = BTreeMap::new();
    for delta in branch.deltas.iter().filter(|delta| delta.is_authored()) {
        let handles: Vec<TextHandle> = find!(
            handle: TextHandle,
            pattern!(delta.commit_metadata(), [{ delta.subject @ repo::message: ?handle }])
        )
        .collect();
        let handle = at_most_one(handles, delta.subject, "legacy commit message")?;
        let message = handle
            .map(|handle| read_text(source.reader(), handle, "legacy commit message"))
            .transpose()?;
        messages.insert(
            LegacyCommitCoordinate {
                branch: branch.branch,
                pin: branch.pin,
                commit: delta.commit,
            },
            message,
        );
    }
    Ok(messages)
}

fn validate_legacy_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts.iter().filter(|fact| fact.a() == &attrs::nudge.id()) {
        let handle = *fact.v::<inlineencodings::Handle<blobencodings::LongString>>();
        let _: View<str> = reader.get(handle).with_context(|| {
            format!("read legacy Habit nudge {}", hex::encode_upper(handle.raw))
        })?;
    }
    for fact in facts
        .iter()
        .filter(|fact| fact.a() == &attrs::condition.id())
    {
        let push = facts.iter().any(|candidate| {
            candidate.e() == fact.e()
                && (candidate.a() == &push_attrs::recipient.id()
                    || candidate.a() == &push_attrs::sender.id())
        });
        if push {
            let _: String = (*fact.v::<inlineencodings::ShortString>())
                .try_from_inline()
                .map_err(|error| anyhow!("decode push-era Habit condition: {error:?}"))?;
        } else {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::LongString>>();
            let _: View<str> = reader.get(handle).with_context(|| {
                format!(
                    "read pull-era Habit condition {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

fn validate_legacy_catalog(
    reader: &PileReader,
    facts: &TribleSet,
    owners: &BTreeMap<Id, BTreeSet<LegacyCommitCoordinate>>,
    messages: &BTreeMap<LegacyCommitCoordinate, Option<String>>,
) -> Result<LegacyCatalog> {
    validate_legacy_payloads(reader, facts)?;
    let habit_ids = ids_of_kind(facts, KIND_HABIT_ID);
    let completion_ids = ids_of_kind(facts, KIND_DONE_ID);
    let state_ids = ids_of_kind(facts, KIND_STATE_ID);

    let mut all = BTreeSet::new();
    for (label, ids) in [
        ("definition", &habit_ids),
        ("completion/fire", &completion_ids),
        ("state event", &state_ids),
    ] {
        for id in ids {
            if !all.insert(*id) {
                bail!("legacy Habit entity {id:X} belongs to more than one record kind ({label})");
            }
        }
    }

    let mut expected = TribleSet::new();
    validate_kind_names(facts, !all.is_empty(), &mut expected)?;

    let mut catalog = LegacyCatalog::default();
    for id in habit_ids {
        let owner = unique_owner(owners, id)?;
        require_kind(facts, id, KIND_HABIT_ID, "definition")?;
        let attributes = attributes_on(facts, id);
        let pull_attributes = BTreeSet::from([
            metadata::tag.id(),
            attrs::label.id(),
            attrs::condition.id(),
            attrs::nudge.id(),
            metadata::created_at.id(),
        ]);
        let push_attributes = BTreeSet::from([
            metadata::tag.id(),
            attrs::label.id(),
            attrs::condition.id(),
            attrs::nudge.id(),
            push_attrs::recipient.id(),
            push_attrs::sender.id(),
            metadata::created_at.id(),
        ]);
        let era = if attributes == pull_attributes {
            DefinitionEra::Pull
        } else if attributes == push_attributes {
            DefinitionEra::Push
        } else {
            bail!("legacy Habit definition {id:X} has an unknown push/pull field set");
        };
        let label = exactly_one(
            find!(value: String, pattern!(facts, [{ id @ attrs::label: ?value }])).collect(),
            id,
            "label",
        )?;
        let nudge_handle = exactly_one(
            find!(value: TextHandle, pattern!(facts, [{ id @ attrs::nudge: ?value }])).collect(),
            id,
            "nudge",
        )?;
        let nudge = read_text(reader, nudge_handle, "legacy Habit nudge")?;
        let condition = match era {
            DefinitionEra::Pull => {
                let handle = exactly_one(
                    find!(value: TextHandle, pattern!(facts, [{ id @ attrs::condition: ?value }]))
                        .collect(),
                    id,
                    "condition",
                )?;
                read_text(reader, handle, "legacy Habit condition")?
            }
            DefinitionEra::Push => exactly_one(
                find!(
                    value: String,
                    pattern!(facts, [{ id @ push_attrs::condition: ?value }])
                )
                .collect(),
                id,
                "push-era condition",
            )?,
        };
        if era == DefinitionEra::Push {
            let _: Id = exactly_one(
                find!(
                    value: Id,
                    pattern!(facts, [{ id @ push_attrs::recipient: ?value }])
                )
                .collect(),
                id,
                "push-era recipient",
            )?;
            let _: Id = exactly_one(
                find!(
                    value: Id,
                    pattern!(facts, [{ id @ push_attrs::sender: ?value }])
                )
                .collect(),
                id,
                "push-era sender",
            )?;
        }
        let at = exactly_one(
            find!(
                value: IntervalValue,
                pattern!(facts, [{ id @ metadata::created_at: ?value }])
            )
            .collect(),
            id,
            "created_at",
        )?;
        point_second(at, &format!("legacy Habit definition {id:X}"))?;
        require_canonical(&label, "legacy Habit label", Some(MAX_LABEL_BYTES))?;
        require_canonical(&condition, "legacy Habit condition", None)?;
        require_canonical(&nudge, "legacy Habit nudge", None)?;
        Condition::parse(&condition)
            .map_err(|error| anyhow!("legacy Habit definition {id:X}: {error}"))?;
        include_entity(facts, id, &mut expected);
        catalog.definitions.insert(
            id,
            LegacyDefinition {
                id,
                era,
                label,
                condition,
                nudge,
            },
        );
        let _ = owner;
    }

    for id in completion_ids {
        let owner = unique_owner(owners, id)?;
        require_kind(facts, id, KIND_DONE_ID, "completion/fire")?;
        require_attributes(
            facts,
            id,
            &[
                metadata::tag.id(),
                attrs::of.id(),
                metadata::created_at.id(),
            ],
            "completion/fire",
        )?;
        let habit = exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ attrs::of: ?value }])).collect(),
            id,
            "of",
        )?;
        let at = exactly_one(
            find!(
                value: IntervalValue,
                pattern!(facts, [{ id @ metadata::created_at: ?value }])
            )
            .collect(),
            id,
            "created_at",
        )?;
        point_second(at, &format!("legacy Habit completion/fire {id:X}"))?;
        let description = messages.get(&owner).and_then(|message| message.as_deref());
        let meaning = match description {
            Some(LEGACY_FIRE_COMMIT_MESSAGE) => CompletionMeaning::Fire,
            Some(LEGACY_EVENT_COMMIT_MESSAGE) => CompletionMeaning::Done,
            other => bail!(
                "legacy Habit completion/fire {id:X} has irreducible meaning under commit description {other:?}"
            ),
        };
        include_entity(facts, id, &mut expected);
        catalog.completions.insert(
            id,
            LegacyCompletion {
                id,
                habit,
                at,
                meaning,
            },
        );
    }

    for id in state_ids {
        unique_owner(owners, id)?;
        require_kind(facts, id, KIND_STATE_ID, "state event")?;
        require_attributes(
            facts,
            id,
            &[
                metadata::tag.id(),
                attrs::of.id(),
                attrs::state.id(),
                metadata::created_at.id(),
            ],
            "state event",
        )?;
        let habit = exactly_one(
            find!(value: Id, pattern!(facts, [{ id @ attrs::of: ?value }])).collect(),
            id,
            "of",
        )?;
        let state = exactly_one(
            find!(value: String, pattern!(facts, [{ id @ attrs::state: ?value }])).collect(),
            id,
            "state",
        )?;
        let state = match state.as_str() {
            STATE_ACTIVE => DeclaredState::Active,
            STATE_PAUSED => DeclaredState::Paused,
            other => bail!("legacy Habit state event {id:X} has unknown state {other:?}"),
        };
        let at = exactly_one(
            find!(
                value: IntervalValue,
                pattern!(facts, [{ id @ metadata::created_at: ?value }])
            )
            .collect(),
            id,
            "created_at",
        )?;
        let second = point_second(at, &format!("legacy Habit state event {id:X}"))?;
        include_entity(facts, id, &mut expected);
        catalog.states.insert(
            id,
            LegacyState {
                id,
                habit,
                state,
                at,
                second,
            },
        );
    }

    for completion in catalog.completions.values() {
        if !catalog.definitions.contains_key(&completion.habit) {
            bail!(
                "legacy Habit completion/fire {:X} names missing definition {:X}",
                completion.id,
                completion.habit
            );
        }
    }
    for state in catalog.states.values() {
        if !catalog.definitions.contains_key(&state.habit) {
            bail!(
                "legacy Habit state event {:X} names missing definition {:X}",
                state.id,
                state.habit
            );
        }
    }

    if expected != *facts {
        let missing = expected.difference(facts).len();
        let unexpected = facts.difference(&expected).len();
        bail!(
            "legacy Habit catalog is not an exact known writer shape ({missing} missing, {unexpected} unexpected facts)"
        );
    }
    Ok(catalog)
}

fn validate_kind_names(facts: &TribleSet, required: bool, expected: &mut TribleSet) -> Result<()> {
    for (kind, allowed) in [
        (KIND_HABIT_ID, &[LEGACY_HABIT_LABEL][..]),
        (KIND_DONE_ID, &[LEGACY_FIRE_LABEL, LEGACY_DONE_LABEL][..]),
        (KIND_STATE_ID, &[LEGACY_STATE_LABEL][..]),
    ] {
        let handles: Vec<TextHandle> = find!(
            handle: TextHandle,
            pattern!(facts, [{ kind @ metadata::name: ?handle }])
        )
        .collect();
        if required && handles.len() != 1 {
            bail!(
                "legacy Habit kind {kind:X} has {} names; expected exactly one",
                handles.len()
            );
        }
        if handles.len() > 1 {
            bail!("legacy Habit kind {kind:X} has competing names");
        }
        if let Some(handle) = handles.first().copied() {
            // The historical `ensure_metadata` writer recorded only the
            // deterministic LongString handle and did not necessarily retain
            // the corresponding blob. Compare that content address directly;
            // requiring a payload would reject a byte-exact writer output.
            let known: BTreeSet<TextHandle> = allowed
                .iter()
                .map(|name| name.to_string().to_blob().get_handle())
                .collect();
            if !known.contains(&handle) {
                bail!(
                    "legacy Habit kind {kind:X} has unknown name handle {}",
                    hex::encode_upper(handle.raw)
                );
            }
            for fact in facts
                .iter()
                .filter(|fact| fact.e() == &kind && fact.a() == &metadata::name.id())
            {
                expected.insert(fact);
            }
        }
    }
    Ok(())
}

fn require_canonical(value: &str, label: &str, max: Option<usize>) -> Result<()> {
    if value.is_empty() || value.trim() != value {
        bail!("{label} is empty or has noncanonical surrounding whitespace");
    }
    if value.bytes().any(|byte| byte == 0) {
        bail!("{label} contains a NUL byte");
    }
    if let Some(max) = max {
        if value.len() > max {
            bail!("{label} exceeds {max} bytes");
        }
    }
    Ok(())
}

fn point_second(value: IntervalValue, label: &str) -> Result<i64> {
    let (lower, upper): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode {label} timestamp: {error:?}"))?;
    if lower != upper {
        bail!("{label} timestamp is not a point");
    }
    i64::try_from(lower / 1_000_000_000)
        .map_err(|_| anyhow!("{label} timestamp lies outside the supported second range"))
}

fn read_text(reader: &PileReader, handle: TextHandle, label: &str) -> Result<String> {
    let value: View<str> = reader
        .get(handle)
        .with_context(|| format!("read {label} {}", hex::encode_upper(handle.raw)))?;
    Ok(value.to_string())
}

fn unique_owner(
    owners: &BTreeMap<Id, BTreeSet<LegacyCommitCoordinate>>,
    entity: Id,
) -> Result<LegacyCommitCoordinate> {
    let owners = owners.get(&entity).cloned().unwrap_or_default();
    if owners.len() != 1 {
        bail!(
            "legacy Habit entity {entity:X} spans {} authored commits; expected one atomic record",
            owners.len()
        );
    }
    Ok(*owners.iter().next().expect("one owner"))
}

fn ids_of_kind(facts: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: kind }])).collect()
}

fn attributes_on(facts: &TribleSet, entity: Id) -> BTreeSet<Id> {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity)
        .map(|fact| *fact.a())
        .collect()
}

fn require_kind(facts: &TribleSet, entity: Id, expected: Id, label: &str) -> Result<()> {
    let actual = exactly_one(
        find!(value: Id, pattern!(facts, [{ entity @ metadata::tag: ?value }])).collect(),
        entity,
        "metadata::tag",
    )?;
    if actual != expected {
        bail!("legacy Habit {label} {entity:X} has an unexpected kind {actual:X}");
    }
    Ok(())
}

fn require_attributes(facts: &TribleSet, entity: Id, expected: &[Id], label: &str) -> Result<()> {
    let actual = attributes_on(facts, entity);
    let expected: BTreeSet<_> = expected.iter().copied().collect();
    if actual != expected {
        bail!("legacy Habit {label} {entity:X} has an unknown field set");
    }
    Ok(())
}

fn include_entity(facts: &TribleSet, entity: Id, expected: &mut TribleSet) {
    for fact in facts.iter().filter(|fact| fact.e() == &entity) {
        expected.insert(fact);
    }
}

fn exactly_one<T>(values: Vec<T>, entity: Id, field: &str) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "legacy Habit entity {entity:X} has {} values for {field}; expected one",
            values.len()
        );
    }
    Ok(values.into_iter().next().expect("one value"))
}

fn at_most_one<T>(values: Vec<T>, entity: Id, field: &str) -> Result<Option<T>> {
    if values.len() > 1 {
        bail!(
            "legacy Habit entity {entity:X} has {} values for {field}; expected at most one",
            values.len()
        );
    }
    Ok(values.into_iter().next())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use triblespace::core::collection::Collection;
    use triblespace::core::repo::{BlobStore, Repository};
    use triblespace::macros::entity;

    use super::*;
    use crate::collection_cutover::{freeze_source};
use faculties::storage::{initialize_signer, load_signer, open_pile_strict};
    use faculties::habits::Activation;

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-habit-cutover-{}-{serial}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Fixture {
        _directory: TestDirectory,
        pile: PathBuf,
        key: PathBuf,
    }

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn at(seconds: f64) -> IntervalValue {
        let epoch = Epoch::from_unix_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn kind_metadata(done_name: &str) -> Fragment {
        let mut fragment = Fragment::empty();
        for (kind, name) in [
            (KIND_HABIT_ID, LEGACY_HABIT_LABEL),
            (KIND_DONE_ID, done_name),
            (KIND_STATE_ID, LEGACY_STATE_LABEL),
        ] {
            // This intentionally reproduces the historical writer bug: only
            // the LongString handle is retained, not the kind-name blob.
            let name: TextHandle = name.to_owned().to_blob().get_handle();
            fragment += entity! { ExclusiveId::force_ref(&kind) @
                metadata::name: name,
            };
        }
        fragment
    }

    fn push_definition(entity: Id, label: &str, condition: &str, when: IntervalValue) -> Fragment {
        let mut fragment = Fragment::empty();
        let nudge: TextHandle = fragment.put("send the old nudge".to_owned());
        fragment += entity! { ExclusiveId::force_ref(&entity) @
            metadata::tag: &KIND_HABIT_ID,
            attrs::label: label,
            push_attrs::condition: condition,
            push_attrs::recipient: id(0x91),
            push_attrs::sender: id(0x92),
            attrs::nudge: nudge,
            metadata::created_at: when,
        };
        fragment
    }

    fn pull_definition(entity: Id, label: &str, condition: &str, when: IntervalValue) -> Fragment {
        let mut fragment = Fragment::empty();
        let condition: TextHandle = fragment.put(condition.to_owned());
        let nudge: TextHandle = fragment.put("do the new thing".to_owned());
        fragment += entity! { ExclusiveId::force_ref(&entity) @
            metadata::tag: &KIND_HABIT_ID,
            attrs::label: label,
            attrs::condition: condition,
            attrs::nudge: nudge,
            metadata::created_at: when,
        };
        fragment
    }

    fn completion(entity: Id, habit: Id, when: IntervalValue) -> Fragment {
        entity! { ExclusiveId::force_ref(&entity) @
            metadata::tag: &KIND_DONE_ID,
            attrs::of: habit,
            metadata::created_at: when,
        }
    }

    fn state(entity: Id, habit: Id, state: DeclaredState, when: IntervalValue) -> Fragment {
        entity! { ExclusiveId::force_ref(&entity) @
            metadata::tag: &KIND_STATE_ID,
            attrs::of: habit,
            attrs::state: state.as_str(),
            metadata::created_at: when,
        }
    }

    fn fixture(commits: Vec<(Fragment, &str)>) -> Fixture {
        let directory = TestDirectory::new();
        let pile = directory.0.join("habit.pile");
        let key = directory.0.join("habit.key");
        File::create(&pile).unwrap();

        let storage = open_pile_strict(&pile).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0xA1; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository.create_branch(LEGACY_BRANCH_NAME, None).unwrap();
        let mut workspace = repository.pull(branch).unwrap();
        for (fragment, message) in commits {
            workspace.commit(fragment, message);
            repository.push(&mut workspace).unwrap();
        }
        repository.close().unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        Fixture {
            _directory: directory,
            pile,
            key,
        }
    }

    fn materialize(fixture: &Fixture) -> (TribleSet, habits::Catalog) {
        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection = Collection::new(pile, DEFAULT_SCOPE_ID, signer);
        let facts = collection.materialize().unwrap();
        let reader = collection.storage_mut().reader().unwrap();
        let catalog = habits::load_catalog(&reader, &facts).unwrap();
        collection.into_storage().close().unwrap();
        (facts, catalog)
    }

    #[test]
    fn exact_additive_plan_preserves_both_eras_and_maps_state_arbitration_to_a_dag() {
        let push = id(0x11);
        let pull = id(0x12);
        let fire = id(0x21);
        let done = id(0x22);
        let first_pause = id(0x31);
        let second_pause = id(0x32);
        let resume = id(0x33);

        let mut first = kind_metadata(LEGACY_FIRE_LABEL);
        first += push_definition(push, "old-loop", "every 1h", at(1.25));
        let fixture = fixture(vec![
            (first, "habit add"),
            (completion(fire, push, at(2.25)), LEGACY_FIRE_COMMIT_MESSAGE),
            (
                pull_definition(pull, "new-loop", "every 2h", at(3.25)),
                "habit add",
            ),
            (
                completion(done, pull, at(4.25)),
                LEGACY_EVENT_COMMIT_MESSAGE,
            ),
            (
                state(first_pause, push, DeclaredState::Paused, at(5.10)),
                "habit pause",
            ),
            (
                state(second_pause, push, DeclaredState::Paused, at(5.90)),
                LEGACY_EVENT_COMMIT_MESSAGE,
            ),
            (
                state(resume, push, DeclaredState::Active, at(6.20)),
                "habit resume",
            ),
            (Fragment::empty(), "authored empty"),
        ]);

        let frozen = freeze_source(&fixture.pile).unwrap();
        let legacy_pins = frozen.legacy_pins().to_vec();
        let plan = plan(&frozen).unwrap();
        assert_eq!(
            plan.report(),
            &HabitMigrationReport {
                authored_commits: 8,
                preserved_facts: 33,
                push_definitions: 1,
                pull_definitions: 1,
                legacy_fires: 1,
                legacy_completions: 1,
                legacy_state_events: 3,
                canonical_definitions: 2,
                canonical_completions: 1,
                canonical_state_assertions: 3,
                canonical_facts: 25,
                output_facts: 58,
            }
        );
        assert_eq!(plan.publication_fragments().len(), 9);
        assert!(plan.commits().last().unwrap().fragment.facts().is_empty());
        assert!(!plan
            .commits()
            .last()
            .unwrap()
            .fragment
            .metafacts()
            .is_empty());
        plan.verify_conservation().unwrap();

        for legacy in [push, pull, fire, done, first_pause, second_pause, resume] {
            assert!(plan.original_facts().iter().any(|fact| fact.e() == &legacy));
            assert!(plan
                .materialized_facts()
                .iter()
                .any(|fact| fact.e() == &legacy));
        }

        let first_publish = publish(&frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        let published_length = fs::metadata(&fixture.pile).unwrap().len();
        let second_publish = publish(&frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(first_publish, second_publish);
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), published_length);

        let (facts, catalog) = materialize(&fixture);
        assert_eq!(facts, plan.materialized_facts());
        assert_eq!(catalog.habits().count(), 2);
        assert_eq!(catalog.completions().count(), 1);
        assert_eq!(catalog.assertions().count(), 3);
        assert!(catalog
            .completions()
            .all(|completion| completion.id != fire));
        let old = catalog.labelled("old-loop");
        assert_eq!(old.len(), 1);
        let old = old[0];
        let activation = catalog.activation(old.id).unwrap();
        let Activation::Active(heads) = activation else {
            panic!("legacy resume did not become an active DAG head");
        };
        assert_eq!(heads.len(), 1);
        assert_eq!(heads[0].predecessors.len(), 2);
        assert!(heads[0].predecessors.iter().all(|predecessor| {
            catalog
                .assertions()
                .find(|assertion| assertion.id == *predecessor)
                .is_some_and(|assertion| assertion.state == DeclaredState::Paused)
        }));
        let new = catalog.labelled("new-loop");
        assert_eq!(new.len(), 1);
        assert!(catalog
            .completions()
            .any(|completion| completion.habit == new[0].id));

        let after = freeze_source(&fixture.pile).unwrap();
        assert_eq!(after.legacy_pins(), legacy_pins);
    }

    #[test]
    fn same_second_state_disagreement_is_rejected_instead_of_inventing_a_winner() {
        let habit = id(0x41);
        let mut first = kind_metadata(LEGACY_DONE_LABEL);
        first += pull_definition(habit, "fork", "every 1h", at(1.0));
        let fixture = fixture(vec![
            (first, "habit add"),
            (
                state(id(0x42), habit, DeclaredState::Paused, at(10.10)),
                LEGACY_EVENT_COMMIT_MESSAGE,
            ),
            (
                state(id(0x43), habit, DeclaredState::Active, at(10.90)),
                LEGACY_EVENT_COMMIT_MESSAGE,
            ),
        ]);

        let frozen = freeze_source(&fixture.pile).unwrap();
        let error = plan(&frozen).unwrap_err();
        assert!(format!("{error:#}").contains("conflicting state events in arbitration second"));
    }

    #[test]
    fn reused_event_kind_requires_the_signed_commit_message_to_resolve_meaning() {
        let habit = id(0x51);
        let mut first = kind_metadata(LEGACY_FIRE_LABEL);
        first += push_definition(habit, "ambiguous", "every 1h", at(1.0));
        let fixture = fixture(vec![
            (first, "habit add"),
            (completion(id(0x52), habit, at(2.0)), "unexpected writer"),
        ]);

        let frozen = freeze_source(&fixture.pile).unwrap();
        let error = plan(&frozen).unwrap_err();
        assert!(format!("{error:#}").contains("irreducible meaning"));
    }

    #[test]
    fn unknown_legacy_field_sets_are_rejected_before_publication() {
        let habit = id(0x61);
        let mut definition = kind_metadata(LEGACY_DONE_LABEL);
        definition += pull_definition(habit, "malformed", "every 1h", at(1.0));
        definition += entity! { ExclusiveId::force_ref(&habit) @
            metadata::supersedes: &habit,
        };
        let fixture = fixture(vec![(definition, "habit add")]);

        let frozen = freeze_source(&fixture.pile).unwrap();
        let error = plan(&frozen).unwrap_err();
        assert!(format!("{error:#}").contains("unknown push/pull field set"));
    }
}
