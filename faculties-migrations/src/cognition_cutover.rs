//! Stopped-world projection of both historical Cognition branches.
//!
//! The provisioned cognition branch carries the later shared event ledger.
//! The earliest playground thought/request pair was instead written to main.
//! Both exact pins are consumed into one native collection. Facts, entity ids,
//! authored partitioning, metadata, and resident attachments are preserved.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::attribute::Attribute;
use triblespace::core::blob::encodings::longstring::LongString;
use triblespace::core::collection::{Collection, CollectionCommit};
use triblespace::core::inline::{Inline, InlineEncoding};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::BlobStore;
use triblespace::prelude::*;

use faculties::cognition;
use crate::collection_cutover::{project_legacy_authored_commits, FrozenSource, LegacyCommitCoordinate, LegacyPinCoordinate};
use faculties::storage::{load_signer, open_pile_strict};
use faculties::schemas::cognition::{DEFAULT_SCOPE_ID, LEGACY_BRANCH_NAME};
use faculties::schemas::triage;

const LEGACY_MAIN_BRANCH_NAME: &str = "main";

/// Historical playground thought tag.
pub const KIND_THOUGHT_ID: Id = triblespace::macros::id_hex!("26FA0606BCF4AA73F868B029596828DB");

mod legacy {
    use super::*;

    attributes! {
        "C1FFE9D4FEC549C09C96639665561DFE" unsafe as model: inlineencodings::ShortString;
        "B6BF5BEE9961D6C0F4F825088DD2C3F2" unsafe as request_context: inlineencodings::Handle<blobencodings::LongString>;
    }
}

type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CognitionMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CognitionMigrationReport {
    pub authored_commits: usize,
    pub authored_empty_commits: usize,
    pub facts: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CognitionMigrationPlan {
    source_pins: [LegacyPinCoordinate; 2],
    commits: Vec<CognitionMigrationCommit>,
    original: TribleSet,
    report: CognitionMigrationReport,
}

impl CognitionMigrationPlan {
    pub const fn source_pins(&self) -> &[LegacyPinCoordinate; 2] {
        &self.source_pins
    }

    pub fn commits(&self) -> &[CognitionMigrationCommit] {
        &self.commits
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    pub const fn report(&self) -> &CognitionMigrationReport {
        &self.report
    }

    pub fn materialized_facts(&self) -> TribleSet {
        self.commits
            .iter()
            .flat_map(|commit| commit.fragment.facts().iter().copied())
            .collect()
    }

    pub fn verify_conservation(&self) -> Result<()> {
        if self.materialized_facts() != self.original {
            bail!("planned Cognition collection does not exactly preserve both legacy branches");
        }
        if self.report.authored_commits != self.commits.len()
            || self.report.facts != self.original.len()
        {
            bail!("Cognition migration report disagrees with its planned commits");
        }
        Ok(())
    }
}

pub fn plan(source: &FrozenSource) -> Result<CognitionMigrationPlan> {
    let cognition_branch = source
        .legacy_branch(LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Cognition branch"))?;
    let main_branch = source
        .legacy_branch(LEGACY_MAIN_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no historical cognition main branch"))?;

    let main_facts: TribleSet = main_branch
        .deltas
        .iter()
        .flat_map(|delta| delta.facts.iter().copied())
        .collect();
    validate_main_catalog(source.reader(), &main_facts)
        .context("validate frozen historical cognition main")?;

    let mut projected = project_legacy_authored_commits(
        source,
        &cognition_branch,
        cognition::validate_known_payloads,
    )
    .context("project frozen Cognition authored commits")?;
    projected.extend(
        project_legacy_authored_commits(source, &main_branch, validate_main_payloads)
            .context("project historical cognition main authored commits")?,
    );
    projected.sort_unstable_by_key(|commit| commit.source);

    let source_pins = [
        cognition_branch.pin_coordinate(),
        main_branch.pin_coordinate(),
    ];
    let mut seen = BTreeSet::new();
    let mut original = TribleSet::new();
    let mut authored_empty_commits = 0;
    let mut commits = Vec::with_capacity(projected.len());
    for projected in projected {
        if !source_pins
            .iter()
            .any(|pin| projected.source.branch == pin.id && projected.source.pin == pin.value)
        {
            bail!("Cognition authored commit belongs to neither frozen source pin");
        }
        if !seen.insert(projected.source) {
            bail!(
                "Cognition migration input repeats legacy authored commit {}",
                hex::encode_upper(projected.source.commit.raw)
            );
        }
        if projected.content.facts().is_empty() {
            authored_empty_commits += 1;
        }
        original += projected.content.facts().clone();
        let mut fragment = projected.content;
        fragment.describe_with(projected.metadata);
        cognition::validate_fragment(&fragment).with_context(|| {
            format!(
                "validate self-contained Cognition commit projected from {}",
                hex::encode_upper(projected.source.commit.raw)
            )
        })?;
        commits.push(CognitionMigrationCommit {
            source: projected.source,
            fragment,
        });
    }

    cognition::validate_catalog(source.reader(), &original)
        .context("validate complete frozen Cognition value")?;
    let plan = CognitionMigrationPlan {
        source_pins,
        report: CognitionMigrationReport {
            authored_commits: commits.len(),
            authored_empty_commits,
            facts: original.len(),
        },
        commits,
        original,
    };
    plan.verify_conservation()?;
    Ok(plan)
}

pub fn publish(
    source: &FrozenSource,
    plan: &CognitionMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    for pin in plan.source_pins {
        if !source.legacy_pins().contains(&pin) {
            bail!("Cognition migration plan does not belong to this frozen source");
        }
    }
    plan.verify_conservation()?;

    let signer = load_signer(target, key)?;
    let pile = open_pile_strict(target)?;
    let mut collection = faculties::collection_names::open(pile, DEFAULT_SCOPE_ID, signer);
    let result = (|| {
        let current = collection
            .materialize()
            .context("materialize existing native Cognition value")?;
        let reader = collection
            .storage_mut()
            .reader()
            .context("open Cognition publication attachment reader")?;
        let mut staged = Fragment::empty();
        for commit in &plan.commits {
            staged += commit.fragment.clone();
        }
        cognition::validate_candidate(&reader, &current, &staged)
            .context("preflight complete post-migration Cognition union")?;

        plan.commits
            .iter()
            .map(|commit| {
                collection.commit(commit.fragment.clone()).with_context(|| {
                    format!(
                        "publish Cognition commit projected from {}",
                        hex::encode_upper(commit.source.commit.raw)
                    )
                })
            })
            .collect()
    })();
    finish_pile(collection.into_storage(), result)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Thought {
    context: TextHandle,
    created_at: IntervalValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Request {
    thought: Id,
    context: TextHandle,
    created_at: IntervalValue,
    model: String,
}

fn inline_values<V: InlineEncoding>(
    facts: &TribleSet,
    entity: Id,
    attribute: &Attribute<V>,
) -> Vec<Inline<V>> {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity && fact.a() == &attribute.id())
        .map(|fact| *fact.v::<V>())
        .collect()
}

fn exactly_one<T>(mut values: Vec<T>, entity: Id, field: &str) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "historical cognition entity {entity:X} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(values.pop().expect("length checked"))
}

fn ids(
    facts: &TribleSet,
    entity: Id,
    attribute: &Attribute<inlineencodings::GenId>,
) -> Result<Vec<Id>> {
    inline_values(facts, entity, attribute)
        .into_iter()
        .map(|value| {
            value
                .try_from_inline()
                .map_err(|error| anyhow!("decode historical cognition id: {error:?}"))
        })
        .collect()
}

fn point_interval(value: IntervalValue, entity: Id, field: &str) -> Result<()> {
    let (lower, upper): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode historical cognition {field}: {error:?}"))?;
    if lower != upper {
        bail!("historical cognition {field} on {entity:X} is not a point interval");
    }
    Ok(())
}

fn read_context(reader: &PileReader, handle: TextHandle, entity: Id, field: &str) -> Result<()> {
    let value: View<str> = reader.get(handle).with_context(|| {
        format!(
            "read historical cognition {field} {} on {entity:X}",
            hex::encode_upper(handle.raw)
        )
    })?;
    if value.trim().is_empty() || value.as_bytes().contains(&0) {
        bail!("historical cognition {field} on {entity:X} is empty or contains NUL");
    }
    let parsed: serde_json::Value = serde_json::from_str(&value)
        .with_context(|| format!("parse historical cognition {field} on {entity:X}"))?;
    if !parsed.is_array() {
        bail!("historical cognition {field} on {entity:X} is not a JSON message array");
    }
    Ok(())
}

fn validate_main_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    cognition::validate_known_payloads(reader, facts)?;
    for fact in facts
        .iter()
        .filter(|fact| fact.a() == &legacy::request_context.id())
    {
        let handle = *fact.v::<inlineencodings::Handle<LongString>>();
        let _: View<str> = reader.get(handle).with_context(|| {
            format!(
                "strictly read historical cognition payload {}",
                hex::encode_upper(handle.raw)
            )
        })?;
    }
    Ok(())
}

fn allowed_attribute(attribute: Id, allowed: &[Id]) -> bool {
    allowed.contains(&attribute)
}

pub(crate) fn validate_main_catalog(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    validate_main_payloads(reader, facts)?;
    let entities: BTreeSet<Id> = facts.iter().map(|fact| *fact.e()).collect();
    let mut thoughts = BTreeMap::new();
    let mut requests = BTreeMap::new();

    for entity in entities {
        let tag = exactly_one(ids(facts, entity, &metadata::tag)?, entity, "metadata::tag")?;
        match tag {
            KIND_THOUGHT_ID => {
                let allowed = [
                    metadata::tag.id(),
                    metadata::created_at.id(),
                    triage::cog::context.id(),
                ];
                if let Some(fact) = facts
                    .iter()
                    .find(|fact| fact.e() == &entity && !allowed_attribute(*fact.a(), &allowed))
                {
                    bail!(
                        "historical cognition thought {entity:X} has unknown attribute {:X}",
                        fact.a()
                    );
                }
                let context = exactly_one(
                    inline_values(facts, entity, &triage::cog::context),
                    entity,
                    "cog::context",
                )?;
                let created_at = exactly_one(
                    inline_values(facts, entity, &metadata::created_at),
                    entity,
                    "metadata::created_at",
                )?;
                point_interval(created_at, entity, "creation time")?;
                read_context(reader, context, entity, "thought context")?;
                thoughts.insert(
                    entity,
                    Thought {
                        context,
                        created_at,
                    },
                );
            }
            triage::KIND_MODEL_REQUEST_ID => {
                let allowed = [
                    metadata::tag.id(),
                    metadata::created_at.id(),
                    legacy::model.id(),
                    legacy::request_context.id(),
                    triage::model_chat::about_thought.id(),
                ];
                if let Some(fact) = facts
                    .iter()
                    .find(|fact| fact.e() == &entity && !allowed_attribute(*fact.a(), &allowed))
                {
                    bail!(
                        "historical cognition request {entity:X} has unknown attribute {:X}",
                        fact.a()
                    );
                }
                let model: String = exactly_one(
                    inline_values(facts, entity, &legacy::model),
                    entity,
                    "model",
                )?
                .try_from_inline()
                .map_err(|error| anyhow!("decode historical cognition model: {error:?}"))?;
                if model.trim().is_empty() || model.trim() != model || model.contains('\0') {
                    bail!("historical cognition model on {entity:X} is not canonical text");
                }
                let thought = exactly_one(
                    ids(facts, entity, &triage::model_chat::about_thought)?,
                    entity,
                    "about_thought",
                )?;
                let context = exactly_one(
                    inline_values(facts, entity, &legacy::request_context),
                    entity,
                    "request context",
                )?;
                let created_at = exactly_one(
                    inline_values(facts, entity, &metadata::created_at),
                    entity,
                    "metadata::created_at",
                )?;
                point_interval(created_at, entity, "creation time")?;
                read_context(reader, context, entity, "request context")?;
                requests.insert(
                    entity,
                    Request {
                        thought,
                        context,
                        created_at,
                        model,
                    },
                );
            }
            other => bail!("historical cognition entity {entity:X} has unknown kind tag {other:X}"),
        }
    }

    if thoughts.is_empty() || requests.is_empty() {
        bail!("historical cognition main must contain at least one complete thought/request pair");
    }
    let mut referenced = BTreeSet::new();
    for (request_id, request) in &requests {
        let thought = thoughts.get(&request.thought).ok_or_else(|| {
            anyhow!(
                "historical cognition request {request_id:X} references absent thought {:X}",
                request.thought
            )
        })?;
        if !referenced.insert(request.thought) {
            bail!(
                "historical cognition thought {:X} is referenced by multiple requests",
                request.thought
            );
        }
        if request.context != thought.context {
            bail!(
                "historical cognition request {request_id:X} does not retain its thought context"
            );
        }
        if request.created_at != thought.created_at {
            bail!(
                "historical cognition request {request_id:X} and thought have different creation times"
            );
        }
    }
    let all_thoughts: BTreeSet<Id> = thoughts.keys().copied().collect();
    if referenced != all_thoughts {
        bail!("historical cognition main contains an unrequested thought");
    }
    Ok(())
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    match (result, pile.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(anyhow!("close Cognition target pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Cognition target pile also failed: {close_error}"
        ))),
    }
}
#[cfg(test)]
mod tests {
    use std::fs::File;

    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use triblespace::core::id::ExclusiveId;
    use triblespace::core::repo::Repository;

    use super::*;
    use crate::collection_cutover::{freeze_source};
use faculties::storage::{open_pile_strict};

    const THOUGHT: Id = triblespace::macros::id_hex!("C1000000000000000000000000000001");
    const REQUEST: Id = triblespace::macros::id_hex!("C1000000000000000000000000000002");

    fn point(seconds: f64) -> IntervalValue {
        let epoch = Epoch::from_tai_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn pair(mismatched_context: bool) -> Fragment {
        let mut fragment = Fragment::empty();
        let thought_context =
            fragment.put::<LongString, _>(r#"[{"role":"user","content":"hello"}]"#.to_owned());
        let request_context = if mismatched_context {
            fragment.put::<LongString, _>(r#"[{"role":"user","content":"different"}]"#.to_owned())
        } else {
            thought_context
        };
        let at = point(42.0);
        fragment += entity! { ExclusiveId::force_ref(&THOUGHT) @
            metadata::tag: &KIND_THOUGHT_ID,
            metadata::created_at: at,
            triage::cog::context: thought_context,
        };
        fragment += entity! { ExclusiveId::force_ref(&REQUEST) @
            metadata::tag: &triage::KIND_MODEL_REQUEST_ID,
            metadata::created_at: at,
            legacy::model: "claude-sonnet-4-6",
            legacy::request_context: request_context,
            triage::model_chat::about_thought: &THOUGHT,
        };
        fragment
    }

    fn populate(path: &Path, mismatched_context: bool) {
        File::create(path).unwrap();
        let pile = open_pile_strict(path).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0xC1; 32]), Fragment::empty()).unwrap();
        repository.create_branch(LEGACY_BRANCH_NAME, None).unwrap();
        let main = *repository
            .create_branch(LEGACY_MAIN_BRANCH_NAME, None)
            .unwrap();
        let mut workspace = repository.pull(main).unwrap();
        workspace.commit(pair(mismatched_context), "historical cognition pair");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();
    }

    #[test]
    fn plan_consumes_empty_cognition_and_preserves_strict_main_pair() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cognition.pile");
        populate(&path, false);

        let frozen = freeze_source(&path).unwrap();
        let plan = plan(&frozen).unwrap();
        assert_eq!(plan.source_pins().len(), 2);
        assert_eq!(plan.report().authored_commits, 1);
        assert_eq!(plan.report().facts, 8);
        assert_eq!(plan.materialized_facts(), *plan.original_facts());
        validate_main_catalog(frozen.reader(), plan.original_facts()).unwrap();
    }

    #[test]
    fn main_request_must_retain_the_exact_thought_context() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cognition.pile");
        populate(&path, true);

        let frozen = freeze_source(&path).unwrap();
        let error = plan(&frozen).unwrap_err();
        assert!(format!("{error:#}").contains("does not retain its thought context"));
    }
}
