//! Work with pull-based standing intentions in one fixed native collection.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::clock;
use crate::collection_names::open_configured;
use crate::habits::{self, DeclaredState, Habit, State};
use crate::schemas::habit::{Condition, DEFAULT_SCOPE_ID};
use crate::storage::{load_signer, open_pile_strict, FactArchive};
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::{
    Collection, CollectionCommit, CollectionSnapshotExt, CollectionStoreExt,
};
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::SnapshotSource;
use triblespace::prelude::*;

#[derive(Clone, Debug)]
pub struct Habits {
    pile: PathBuf,
    key: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct AddedHabit {
    pub id: Id,
    pub label: String,
    pub cooldown_secs: i64,
    pub script: Option<(String, usize)>,
    pub supersedes: Vec<Id>,
    pub sharing: Vec<Id>,
    pub already_present: bool,
}
#[derive(Clone, Debug)]
pub struct HabitObservation {
    pub definition: Habit,
    pub superseded: bool,
}
#[derive(Clone, Debug)]
pub struct EvaluatedHabit {
    pub row: habits::HabitRow,
    pub state: Option<State>,
}
#[derive(Clone, Debug)]
pub struct HabitList {
    pub entries: Vec<EvaluatedHabit>,
    pub observed_seconds: i64,
    pub superseded: usize,
}
#[derive(Clone, Debug)]
pub struct HabitOccurrence {
    pub habit: Id,
    pub label: String,
    pub event: Id,
}
#[derive(Clone, Debug)]
pub struct HabitStateChange {
    pub habit: Id,
    pub label: String,
    pub event: Option<Id>,
    pub state: DeclaredState,
}

impl Habits {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self { pile, key }
    }
    /// Literal resident definition inputs. This stores but never runs a script.
    pub fn add(
        &self,
        label: &str,
        condition: &str,
        nudge: &str,
        script: Option<&[u8]>,
        supersedes: &[String],
    ) -> Result<AddedHabit> {
        let cooldown_secs = Condition::parse(condition.trim())
            .map_err(anyhow::Error::msg)?
            .cooldown_secs;
        let carried = script.map(|bytes| (habits::script_digest(bytes), bytes.len()));
        with_habits(&self.pile, self.key.as_deref(), |session| {
            let definitions = habits::definitions(&session.reader, &session.facts)?;
            let superseded = habits::superseded_definition_ids(&session.facts);
            let mut retiring = supersedes
                .iter()
                .map(|s| resolve_predecessor(&definitions, s))
                .collect::<Result<Vec<_>>>()?;
            retiring.sort_unstable();
            retiring.dedup();
            let (fragment, id) = habits::habit_fragment(
                label,
                condition,
                nudge,
                script.map(<[u8]>::to_vec),
                &retiring,
            )?;
            let already_present = definitions.iter().any(|habit| habit.id == id);
            let sharing = definitions
                .iter()
                .filter(|habit| !superseded.contains(&habit.id))
                .filter(|habit| {
                    habit.id != id
                        && habit.label.eq_ignore_ascii_case(label.trim())
                        && !retiring.contains(&habit.id)
                })
                .map(|habit| habit.id)
                .collect();
            if !already_present {
                session.commit(fragment)?;
            }
            Ok(AddedHabit {
                id,
                label: label.trim().to_owned(),
                cooldown_secs,
                script: carried,
                supersedes: retiring,
                sharing,
                already_present,
            })
        })
    }
    /// Inspect one exact definition or unambiguous label; history stays readable.
    pub fn show(&self, selector: &str) -> Result<HabitObservation> {
        with_habits(&self.pile, self.key.as_deref(), |session| {
            let definitions = habits::definitions(&session.reader, &session.facts)?;
            let definition = select_habit(&definitions, selector)?.clone();
            Ok(HabitObservation {
                superseded: habits::is_superseded(&session.facts, definition.id),
                definition,
            })
        })
    }
    /// Observe live rows. Execution is explicit: when evaluate_conditions is
    /// true, stored predicates run in the pile directory after the frozen
    /// observation has been acquired and storage closed.
    pub fn list(&self, evaluate_conditions: bool) -> Result<HabitList> {
        let (rows, superseded) = with_habits(&self.pile, self.key.as_deref(), |session| {
            let rows = habits::rows(&session.reader, &session.facts)?;
            let ids = habits::definition_ids(&session.facts);
            let superseded = habits::superseded_definition_ids(&session.facts);
            Ok((rows, ids.intersection(&superseded).count()))
        })?;
        let observed_seconds = (clock::tai_nanoseconds_now()? / 1_000_000_000) as i64;
        let at = habits::evaluation_dir(&self.pile);
        let entries = rows
            .into_iter()
            .map(|row| {
                let state =
                    evaluate_conditions.then(|| habits::evaluate(&row, observed_seconds, &at));
                EvaluatedHabit { row, state }
            })
            .collect();
        Ok(HabitList {
            entries,
            observed_seconds,
            superseded,
        })
    }
    pub fn done(&self, selector: &str) -> Result<HabitOccurrence> {
        with_habits(&self.pile, self.key.as_deref(), |session| {
            let definitions = habits::definitions(&session.reader, &session.facts)?;
            let superseded = habits::superseded_definition_ids(&session.facts);
            let habit = select_live_habit(&definitions, &superseded, selector)?.clone();
            let (fragment, event) = habits::completion_fragment(habit.id, clock::point_now()?)?;
            session.commit(fragment)?;
            Ok(HabitOccurrence {
                habit: habit.id,
                label: habit.label,
                event,
            })
        })
    }
    pub fn set_state(&self, selector: &str, state: DeclaredState) -> Result<HabitStateChange> {
        with_habits(&self.pile, self.key.as_deref(), |session| {
            let definitions = habits::definitions(&session.reader, &session.facts)?;
            let superseded = habits::superseded_definition_ids(&session.facts);
            let habit = select_live_habit(&definitions, &superseded, selector)?.clone();
            let activation = habits::activation(&session.facts, habit.id)?;
            let event = if activation.declared() == Some(state) {
                None
            } else {
                let (fragment, id) = habits::state_fragment(
                    habit.id,
                    state,
                    &activation.head_ids(),
                    clock::point_now()?,
                )?;
                session.commit(fragment)?;
                Some(id)
            };
            Ok(HabitStateChange {
                habit: habit.id,
                label: habit.label,
                event,
                state,
            })
        })
    }
    /// Explicit whole-collection audit; ordinary reads do not build a catalog.
    pub fn check(&self) -> Result<String> {
        let catalog = habits::read_catalog_strict(&self.pile, self.key.as_deref())?;
        Ok(format!(
            "Habit collection {} (scope {DEFAULT_SCOPE_ID:X}): {} definitions ({} live, {} carrying their own script), {} completions, {} state assertions validated",
            hex::encode_upper(habits::collection_handle(&self.pile, self.key.as_deref())?.raw),
            catalog.habits().count(), catalog.live().len(),
            catalog.habits().filter(|habit| habit.script.is_some()).count(),
            catalog.completions().count(), catalog.assertions().count()
        ))
    }
}

/// One command-scoped view over the maintained Habit relation.
struct HabitSession<'a> {
    pile: &'a mut Pile,
    collection: Collection<SimpleArchive>,
    signer: &'a SigningKey,
    facts: FactArchive,
    reader: PileSnapshot,
}

impl HabitSession<'_> {
    fn commit(&mut self, fragment: Fragment) -> Result<CollectionCommit> {
        self.pile
            .commit(self.collection, self.signer, fragment)
            .context("commit Habit fragment")
    }
}

fn with_habits<T>(
    pile_path: &Path,
    key_path: Option<&Path>,
    operation: impl FnOnce(&mut HabitSession<'_>) -> Result<T>,
) -> Result<T> {
    let signer = load_signer(pile_path, key_path)?;
    let mut pile = open_pile_strict(pile_path)?;
    let result = (|| {
        let collection = open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
        let descriptor_snapshot = pile.snapshot()?;
        let policy = collection.policy(&descriptor_snapshot)?;
        drop(descriptor_snapshot);
        let maintained_succinct =
            pile.derive::<SuccinctArchiveBlob>(collection, (), policy.clone())?;
        let maintained_rank9 =
            pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(maintained_succinct, (), policy)?;
        let reader = pollster::block_on(async {
            drop(pile.ensure(collection).await?);
            drop(pile.maintain(maintained_succinct).await?);
            pile.maintain(maintained_rank9).await
        })
        .context("maintain Habit fact collection")?;
        let facts = reader
            .collection(maintained_rank9)
            .context("observe maintained Habit fact collection")?
            .view::<FactArchive>()
            .context("read maintained Habit fact collection")?;
        operation(&mut HabitSession {
            pile: &mut pile,
            collection,
            signer: &signer,
            facts,
            reader,
        })
    })();
    match (result, pile.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(anyhow!("close Habit pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Habit pile also failed: {close_error}")))
        }
    }
}

fn id_list(habits: &[&Habit]) -> String {
    habits
        .iter()
        .map(|habit| habit.id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|id| format!("{id:x}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn unique_projection<'a>(definitions: Vec<&'a Habit>, id: Id) -> Result<&'a Habit> {
    match definitions.as_slice() {
        [habit] => Ok(*habit),
        [] => bail!("no Habit definition {id:x}"),
        many => bail!(
            "Habit {id:x} has {} complete projections; its modeled fields are ambiguous",
            many.len()
        ),
    }
}

/// Resolve a command-line selector to exactly one live definition.
///
/// A label is a display name, not a key — several definitions may carry it, and
/// none of them owns it. So a selector is a label *or* an intrinsic id prefix,
/// and an ambiguous label is reported with its candidates rather than resolved
/// by picking one. Picking one is the distributed bug: which definition a name
/// resolves to would then depend on which facts this window happens to have
/// observed, and two windows would disagree while each was locally correct.
fn select_live_habit<'a>(
    definitions: &'a [Habit],
    superseded: &BTreeSet<Id>,
    selector: &str,
) -> Result<&'a Habit> {
    let selector = selector.trim();
    let live: Vec<_> = definitions
        .iter()
        .filter(|habit| !superseded.contains(&habit.id))
        .filter(|habit| habit.label.eq_ignore_ascii_case(selector))
        .collect();
    match live.as_slice() {
        [habit] => return Ok(*habit),
        [] => {}
        many => bail!(
            "label {selector:?} names {} live Habits; address one by id: {}",
            many.len(),
            id_list(many)
        ),
    }

    let ids: BTreeSet<_> = definitions.iter().map(|habit| habit.id).collect();
    let id = crate::resolve_id_prefix(selector, ids)
        .map_err(|error| anyhow!("no Habit labelled {selector:?}, and {error}"))?;
    if superseded.contains(&id) {
        bail!("Habit {id:x} is superseded history and cannot be mutated");
    }
    unique_projection(
        definitions.iter().filter(|habit| habit.id == id).collect(),
        id,
    )
}

/// Resolve any definition, including superseded history, for inspection.
fn select_habit<'a>(definitions: &'a [Habit], selector: &str) -> Result<&'a Habit> {
    let selector = selector.trim();
    let labelled: Vec<_> = definitions
        .iter()
        .filter(|habit| habit.label.eq_ignore_ascii_case(selector))
        .collect();
    match labelled.as_slice() {
        [habit] => return Ok(*habit),
        [] => {}
        many => bail!(
            "label {selector:?} names {} Habit revisions; address one by id: {}",
            many.len(),
            id_list(many)
        ),
    }

    let ids: BTreeSet<_> = definitions.iter().map(|habit| habit.id).collect();
    let id = crate::resolve_id_prefix(selector, ids)
        .map_err(|error| anyhow!("no Habit labelled {selector:?}, and {error}"))?;
    unique_projection(
        definitions.iter().filter(|habit| habit.id == id).collect(),
        id,
    )
}

/// Resolve one revision predecessor by intrinsic id or id prefix.
///
/// A full id deliberately need not be present in this partial view. The model
/// permits a successor to arrive before the definition it retires; once that
/// predecessor arrives, the already-authored edge retires it monotonically.
fn resolve_predecessor(definitions: &[Habit], selector: &str) -> Result<Id> {
    let ids: BTreeSet<_> = definitions.iter().map(|habit| habit.id).collect();
    crate::resolve_id_prefix(selector, ids)
        .map_err(|error| anyhow!("invalid superseded Habit id {selector:?}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::habits::cli::Cli;
    use crate::storage::initialize_signer;
    use clap::CommandFactory;

    #[test]
    fn permanent_cli_has_no_branch_scope_head_or_migration_surface() {
        let command = Cli::command();
        for forbidden in ["branch", "branch_id", "scope", "head", "migrate"] {
            assert!(!command
                .get_arguments()
                .any(|argument| argument.get_id() == forbidden));
            assert!(command.find_subcommand(forbidden).is_none());
        }
    }

    #[test]
    fn mutation_selection_never_targets_superseded_history() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("habit.pile");
        let key = directory.path().join("habit.key");
        std::fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();

        let (original, original_id) =
            habits::habit_fragment("sweep", "every 1h", "sweep", None, &[]).unwrap();
        habits::publish(&pile, Some(&key), original).unwrap();
        let (successor, successor_id) =
            habits::habit_fragment("sweep", "every 2h", "sweep", None, &[original_id]).unwrap();
        habits::publish(&pile, Some(&key), successor).unwrap();

        let (definitions, superseded) = with_habits(&pile, Some(&key), |session| {
            Ok((
                habits::definitions(&session.reader, &session.facts)?,
                habits::superseded_definition_ids(&session.facts),
            ))
        })
        .unwrap();
        assert_eq!(
            select_live_habit(&definitions, &superseded, "sweep")
                .unwrap()
                .id,
            successor_id
        );
        let error =
            select_live_habit(&definitions, &superseded, &format!("{original_id:x}")).unwrap_err();
        assert!(
            error.to_string().contains("superseded history"),
            "{error:#}"
        );
        assert_eq!(
            select_habit(&definitions, &format!("{original_id:x}"))
                .unwrap()
                .id,
            original_id
        );
        let error = select_habit(&definitions, "sweep").unwrap_err();
        assert!(error.to_string().contains("2 Habit revisions"), "{error:#}");
    }

    #[test]
    fn a_full_unseen_id_is_a_valid_revision_predecessor() {
        let definitions = Vec::new();
        let unseen = Id::new([0xA5; 16]).unwrap();
        assert_eq!(
            resolve_predecessor(&definitions, &format!("{unseen:x}")).unwrap(),
            unseen
        );
        assert!(resolve_predecessor(&definitions, "a5a5").is_err());
    }
}
