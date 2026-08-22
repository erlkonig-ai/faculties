//! Stopped-world reconstruction of the legacy Decide ledger.
//!
//! The old writer kept proposal and resolution facts on one random decision
//! anchor. Factors were random entities and a resolution mutated the anchor.
//! The collection ontology instead keeps the anchor stable, makes proposals
//! and factors intrinsic, and represents resolutions as a predecessor DAG.
//! Repository ancestry is the missing structure: it tells us exactly which
//! factors and earlier resolutions were visible to each authored resolution.
//! No clock or iteration order participates in that reconstruction.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::attribute::Attribute;
use triblespace::core::blob::encodings::utf8string::UTF8String;
use triblespace::core::blob::encodings::wasmcode::WasmCode;
use triblespace::core::blob::Blob;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::{Inline, InlineEncoding};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStoreGet, CommitHandle};
use triblespace::core::trible::{Fragment, TribleSet};
use triblespace::prelude::inlineencodings::GenId;
use triblespace::prelude::View;

use crate::collection_cutover::{project_legacy_authored_commits, FrozenLegacyBranch, FrozenSource, LegacyCommitCoordinate, LegacyPinCoordinate, ProjectedLegacyCommit};
use faculties::storage::{publish_fragments};
use faculties::decide::{self as capability, FactorSide, IntervalValue, TextHandle};
use faculties::schemas::decide::{self as schema, decide, factor, KIND_CON, KIND_DECISION, KIND_PRO};

pub use faculties::schemas::decide::LEGACY_BRANCH_NAME;

#[derive(Clone, Debug, Eq, PartialEq)]
struct LegacyDecision {
    id: Id,
    title: TextHandle,
    context: Option<TextHandle>,
    about: Option<Id>,
    created_at: IntervalValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LegacyFactor {
    id: Id,
    decision: Id,
    side: FactorSide,
    text: TextHandle,
    created_at: IntervalValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LegacyCatalog {
    decisions: BTreeMap<Id, LegacyDecision>,
    factors: BTreeMap<Id, LegacyFactor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LegacyResolutionOccurrence {
    source: LegacyCommitCoordinate,
    decision: Id,
    outcome: TextHandle,
    finished_at: IntervalValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BuiltFactor {
    id: Id,
    decision: Id,
    side: FactorSide,
    source_commit: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BuiltResolution {
    id: Id,
    decision: Id,
    source_commit: [u8; 32],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DecideRewriteReport {
    pub authored_commits: usize,
    pub authored_empty_commits: usize,
    pub contentless_merges: usize,
    pub legacy_decisions: usize,
    pub canonical_factors: usize,
    pub canonical_resolutions: usize,
    pub input_unique_facts: usize,
    pub output_facts: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecideCommitPartition {
    pub source: LegacyCommitCoordinate,
    pub content: Fragment,
    pub metadata: Fragment,
    preserved: Fragment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionedDecideRewrite {
    pub content: Fragment,
    pub commits: Vec<DecideCommitPartition>,
    pub report: DecideRewriteReport,
}

/// One native commit planned from one legacy authored commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecideMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
    preserved: Fragment,
}

impl DecideMigrationCommit {
    /// Exact authored content, metadata, and resident blobs retained by this
    /// additive native commit.
    pub fn preserved_fragment(&self) -> &Fragment {
        &self.preserved
    }
}

/// Pure, stopped-world Decide migration plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecideMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<DecideMigrationCommit>,
    original: TribleSet,
    additions: TribleSet,
    report: DecideRewriteReport,
}

impl DecideMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[DecideMigrationCommit] {
        &self.commits
    }

    pub const fn report(&self) -> &DecideRewriteReport {
        &self.report
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    pub fn added_facts(&self) -> &TribleSet {
        &self.additions
    }

    pub fn materialized_facts(&self) -> TribleSet {
        self.commits
            .iter()
            .flat_map(|commit| commit.fragment.facts().iter().copied())
            .collect()
    }

    /// Recheck the additive law and per-commit preservation proof.
    pub fn verify_conservation(&self) -> Result<()> {
        let mut expected = self.original.clone();
        expected += self.additions.clone();
        if self.materialized_facts() != expected {
            bail!("planned Decide collection is not exactly legacy facts union canonical shadows");
        }
        for commit in &self.commits {
            let mut retained = commit.fragment.clone();
            retained += commit.preserved.clone();
            if retained != commit.fragment {
                bail!(
                    "Decide commit projected from {} dropped authored content, metadata, or resident blobs",
                    hex::encode_upper(commit.source.commit.raw)
                );
            }
        }
        if self.report.input_unique_facts != self.original.len()
            || self.report.output_facts != expected.len()
        {
            bail!("Decide migration report disagrees with the planned facts");
        }
        Ok(())
    }

    fn validate(&self, reader: &PileReader) -> Result<()> {
        self.verify_conservation()?;
        let mut complete = Fragment::empty();
        for commit in &self.commits {
            complete += commit.fragment.clone();
        }
        let validated = capability::validate_catalog_union(reader, &TribleSet::new(), &complete)
            .context("validate planned Decide collection and attachments")?;
        if validated != self.materialized_facts() {
            bail!("planned Decide fragment union changed during validation");
        }
        Ok(())
    }
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

fn ids(facts: &TribleSet, entity: Id, attribute: &Attribute<GenId>) -> Result<Vec<Id>> {
    inline_values(facts, entity, attribute)
        .into_iter()
        .map(|value| {
            value
                .try_from_inline()
                .map_err(|error| anyhow!("decode Decide id value: {error:?}"))
        })
        .collect()
}

fn exactly_one<T>(mut values: Vec<T>, entity: Id, field: &str) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "legacy Decide entity {entity:X} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(values.pop().unwrap())
}

fn at_most_one<T>(mut values: Vec<T>, entity: Id, field: &str) -> Result<Option<T>> {
    if values.len() > 1 {
        bail!(
            "legacy Decide entity {entity:X} has {} values for {field}; expected at most one",
            values.len()
        );
    }
    Ok(values.pop())
}

fn point_interval(value: IntervalValue, entity: Id, field: &str) -> Result<()> {
    let (lower, upper): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode legacy Decide {field}: {error:?}"))?;
    if lower != upper {
        bail!("legacy Decide entity {entity:X} has a non-point {field}");
    }
    Ok(())
}

fn read_text(reader: &PileReader, handle: TextHandle, field: &str, entity: Id) -> Result<String> {
    let value: View<str> = reader.get(handle).with_context(|| {
        format!(
            "read legacy Decide {field} payload {} on {entity:X}",
            hex::encode_upper(handle.raw)
        )
    })?;
    if value.trim().is_empty() || value.as_bytes().contains(&0) {
        bail!("legacy Decide {field} on {entity:X} is empty or contains NUL");
    }
    Ok(value.to_string())
}

fn validate_legacy_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts {
        let text_field = if fact.a() == &metadata::name.id() {
            Some("metadata::name")
        } else if fact.a() == &metadata::description.id() {
            Some("metadata::description")
        } else if fact.a() == &metadata::iri.id() {
            Some("metadata::iri")
        } else if fact.a() == &metadata::source.id() {
            Some("metadata::source")
        } else if fact.a() == &metadata::source_module.id() {
            Some("metadata::source_module")
        } else if fact.a() == &decide::outcome.id() {
            Some("decide::outcome")
        } else {
            None
        };
        if let Some(field) = text_field {
            let handle = *fact.v::<Handle<UTF8String>>();
            let _: View<str> = reader.get(handle).with_context(|| {
                format!(
                    "read legacy Decide {field} payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
            continue;
        }
        if fact.a() == &metadata::value_formatter.id() {
            let handle = *fact.v::<Handle<WasmCode>>();
            let _: Blob<WasmCode> = reader.get(handle).with_context(|| {
                format!(
                    "read legacy Decide value formatter {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

fn allowed_attribute(attribute: Id, allowed: &[Id]) -> bool {
    allowed.contains(&attribute)
}

fn load_legacy_catalog(reader: &PileReader, facts: &TribleSet) -> Result<LegacyCatalog> {
    let entities: BTreeSet<Id> = facts.iter().map(|fact| *fact.e()).collect();
    let kind_labels = [
        (KIND_DECISION, "decide-decision"),
        (KIND_PRO, "decide-pro"),
        (KIND_CON, "decide-con"),
    ];
    let kind_ids: BTreeSet<Id> = kind_labels.iter().map(|(id, _)| *id).collect();
    let mut decisions = BTreeMap::new();
    let mut factors = BTreeMap::new();

    for (kind, label) in kind_labels {
        let name = inline_values(facts, kind, &metadata::name);
        if name.is_empty() {
            continue;
        }
        let handle = exactly_one(name, kind, "kind metadata::name")?;
        if read_text(reader, handle, "kind name", kind)? != label {
            bail!("legacy Decide kind {kind:X} has the wrong label");
        }
        let count = facts.iter().filter(|fact| fact.e() == &kind).count();
        if count != 1 {
            bail!("legacy Decide kind {kind:X} has {count} facts; expected one name fact");
        }
    }

    for entity in entities {
        let tags = ids(facts, entity, &metadata::tag)?;
        if tags.is_empty() {
            if kind_ids.contains(&entity) {
                continue;
            }
            bail!("legacy Decide entity {entity:X} has no kind tag");
        }
        let tag = exactly_one(tags, entity, "metadata::tag")?;
        match tag {
            KIND_DECISION => {
                let allowed = [
                    metadata::tag.id(),
                    metadata::name.id(),
                    metadata::description.id(),
                    metadata::created_at.id(),
                    metadata::finished_at.id(),
                    decide::about.id(),
                    decide::outcome.id(),
                ];
                if let Some(fact) = facts
                    .iter()
                    .find(|fact| fact.e() == &entity && !allowed_attribute(*fact.a(), &allowed))
                {
                    bail!(
                        "legacy Decide decision {entity:X} has unknown attribute {:X}",
                        fact.a()
                    );
                }
                let row = LegacyDecision {
                    id: entity,
                    title: exactly_one(
                        inline_values(facts, entity, &metadata::name),
                        entity,
                        "metadata::name",
                    )?,
                    context: at_most_one(
                        inline_values(facts, entity, &metadata::description),
                        entity,
                        "metadata::description",
                    )?,
                    about: at_most_one(
                        ids(facts, entity, &decide::about)?,
                        entity,
                        "decide::about",
                    )?,
                    created_at: exactly_one(
                        inline_values(facts, entity, &metadata::created_at),
                        entity,
                        "metadata::created_at",
                    )?,
                };
                point_interval(row.created_at, entity, "creation time")?;
                read_text(reader, row.title, "title", entity)?;
                if let Some(context) = row.context {
                    read_text(reader, context, "context", entity)?;
                }
                decisions.insert(entity, row);
            }
            KIND_PRO | KIND_CON => {
                let allowed = [
                    metadata::tag.id(),
                    metadata::name.id(),
                    metadata::created_at.id(),
                    factor::about_decision.id(),
                ];
                let facts_for_entity: Vec<_> =
                    facts.iter().filter(|fact| fact.e() == &entity).collect();
                if facts_for_entity.len() != 4 {
                    bail!(
                        "legacy Decide factor {entity:X} has {} facts; expected four",
                        facts_for_entity.len()
                    );
                }
                if let Some(fact) = facts_for_entity
                    .iter()
                    .find(|fact| !allowed_attribute(*fact.a(), &allowed))
                {
                    bail!(
                        "legacy Decide factor {entity:X} has unknown attribute {:X}",
                        fact.a()
                    );
                }
                let row = LegacyFactor {
                    id: entity,
                    decision: exactly_one(
                        ids(facts, entity, &factor::about_decision)?,
                        entity,
                        "factor::about_decision",
                    )?,
                    side: if tag == KIND_PRO {
                        FactorSide::Pro
                    } else {
                        FactorSide::Con
                    },
                    text: exactly_one(
                        inline_values(facts, entity, &metadata::name),
                        entity,
                        "metadata::name",
                    )?,
                    created_at: exactly_one(
                        inline_values(facts, entity, &metadata::created_at),
                        entity,
                        "metadata::created_at",
                    )?,
                };
                point_interval(row.created_at, entity, "factor creation time")?;
                read_text(reader, row.text, "factor text", entity)?;
                factors.insert(entity, row);
            }
            other => bail!("legacy Decide entity {entity:X} has unknown kind marker {other:X}"),
        }
    }

    for factor in factors.values() {
        if !decisions.contains_key(&factor.decision) {
            bail!(
                "legacy Decide factor {:X} names missing decision {:X}",
                factor.id,
                factor.decision
            );
        }
    }
    Ok(LegacyCatalog { decisions, factors })
}

fn collect_resolution_occurrences(
    authored: &[ProjectedLegacyCommit],
    catalog: &LegacyCatalog,
) -> Result<Vec<LegacyResolutionOccurrence>> {
    let mut occurrences = Vec::new();
    for commit in authored {
        let entities: BTreeSet<Id> = commit
            .content
            .facts()
            .iter()
            .filter(|fact| {
                fact.a() == &decide::outcome.id() || fact.a() == &metadata::finished_at.id()
            })
            .map(|fact| *fact.e())
            .collect();
        for decision in entities {
            if !catalog.decisions.contains_key(&decision) {
                bail!("legacy Decide resolution delta names non-decision {decision:X}");
            }
            let outcomes = inline_values(commit.content.facts(), decision, &decide::outcome);
            let finished = inline_values(commit.content.facts(), decision, &metadata::finished_at);
            if outcomes.len() != 1 || finished.len() != 1 {
                bail!(
                    "legacy Decide commit {} has {} outcomes and {} finish times for {decision:X}; pairing is ambiguous",
                    hex::encode_upper(commit.source.commit.raw),
                    outcomes.len(),
                    finished.len()
                );
            }
            point_interval(finished[0], decision, "resolution finish time")?;
            occurrences.push(LegacyResolutionOccurrence {
                source: commit.source,
                decision,
                outcome: outcomes[0],
                finished_at: finished[0],
            });
        }
    }
    Ok(occurrences)
}

fn ancestry(branch: &FrozenLegacyBranch) -> Result<BTreeMap<[u8; 32], BTreeSet<[u8; 32]>>> {
    let mut closure = BTreeMap::<[u8; 32], BTreeSet<[u8; 32]>>::new();
    for delta in &branch.deltas {
        let mut ancestors = BTreeSet::from([delta.commit.raw]);
        for parent in &delta.parents {
            let parent_ancestors = closure.get(&parent.raw).ok_or_else(|| {
                anyhow!(
                    "legacy Decide commit {} precedes parent {}",
                    hex::encode_upper(delta.commit.raw),
                    hex::encode_upper(parent.raw)
                )
            })?;
            ancestors.extend(parent_ancestors.iter().copied());
        }
        if closure.insert(delta.commit.raw, ancestors).is_some() {
            bail!(
                "legacy Decide branch repeats commit {}",
                hex::encode_upper(delta.commit.raw)
            );
        }
    }
    Ok(closure)
}

fn first_witness(
    authored: &[ProjectedLegacyCommit],
    entity: Id,
    attribute: Id,
) -> Result<LegacyCommitCoordinate> {
    authored
        .iter()
        .find(|commit| {
            commit
                .content
                .facts()
                .iter()
                .any(|fact| fact.e() == &entity && fact.a() == &attribute)
        })
        .map(|commit| commit.source)
        .ok_or_else(|| anyhow!("legacy Decide entity {entity:X} has no defining source witness"))
}

fn maximal_resolution_predecessors(
    decision: Id,
    current_commit: [u8; 32],
    built: &[BuiltResolution],
    closure: &BTreeMap<[u8; 32], BTreeSet<[u8; 32]>>,
) -> Result<Vec<Id>> {
    let current_ancestors = closure.get(&current_commit).ok_or_else(|| {
        anyhow!(
            "missing ancestry for legacy Decide commit {}",
            hex::encode_upper(current_commit)
        )
    })?;
    let candidates: Vec<&BuiltResolution> = built
        .iter()
        .filter(|row| {
            row.decision == decision
                && row.source_commit != current_commit
                && current_ancestors.contains(&row.source_commit)
        })
        .collect();
    let mut heads = Vec::new();
    'candidate: for candidate in &candidates {
        for other in &candidates {
            if candidate.source_commit == other.source_commit {
                continue;
            }
            if closure
                .get(&other.source_commit)
                .is_some_and(|ancestors| ancestors.contains(&candidate.source_commit))
            {
                continue 'candidate;
            }
        }
        heads.push(candidate.id);
    }
    heads.sort_unstable();
    heads.dedup();
    Ok(heads)
}

/// Reconstruct the complete collection ontology while retaining one signed
/// commit for every authored legacy delta, including authored-empty deltas.
pub fn rewrite_decide_authored_commits(
    branch: &FrozenLegacyBranch,
    authored: &[ProjectedLegacyCommit],
    reader: &PileReader,
) -> Result<PartitionedDecideRewrite> {
    let expected_authored: Vec<CommitHandle> = branch
        .deltas
        .iter()
        .filter(|delta| delta.is_authored())
        .map(|delta| delta.commit)
        .collect();
    let actual_authored: Vec<CommitHandle> =
        authored.iter().map(|commit| commit.source.commit).collect();
    if actual_authored != expected_authored {
        bail!("legacy Decide authored commits do not match the frozen repository DAG");
    }
    for commit in authored {
        if commit.source.branch != branch.branch || commit.source.pin != branch.pin {
            bail!("legacy Decide authored commit belongs to another frozen pin");
        }
    }

    let mut source_facts = TribleSet::new();
    for commit in authored {
        source_facts += commit.content.facts().clone();
    }
    let catalog = load_legacy_catalog(reader, &source_facts)?;
    let mut occurrences = collect_resolution_occurrences(authored, &catalog)?;
    for occurrence in &occurrences {
        read_text(
            reader,
            occurrence.outcome,
            "resolution outcome",
            occurrence.decision,
        )?;
    }
    let closure = ancestry(branch)?;
    let topo: BTreeMap<[u8; 32], usize> = branch
        .deltas
        .iter()
        .enumerate()
        .map(|(index, delta)| (delta.commit.raw, index))
        .collect();
    occurrences.sort_unstable_by_key(|row| {
        (
            topo.get(&row.source.commit.raw)
                .copied()
                .unwrap_or(usize::MAX),
            row.decision,
        )
    });
    for pair in occurrences.windows(2) {
        if pair[0].source.commit == pair[1].source.commit && pair[0].decision == pair[1].decision {
            bail!(
                "legacy Decide commit {} carries two resolution occurrences for {:X}",
                hex::encode_upper(pair[0].source.commit.raw),
                pair[0].decision
            );
        }
    }

    let mut commits: Vec<DecideCommitPartition> = authored
        .iter()
        .map(|commit| DecideCommitPartition {
            source: commit.source,
            content: commit.content.clone(),
            metadata: commit.metadata.clone(),
            preserved: commit.content.clone(),
        })
        .collect();
    let commit_index: BTreeMap<LegacyCommitCoordinate, usize> = commits
        .iter()
        .enumerate()
        .map(|(index, commit)| (commit.source, index))
        .collect();

    for decision in catalog.decisions.values() {
        let source = first_witness(authored, decision.id, metadata::name.id())?;
        let title = read_text(reader, decision.title, "title", decision.id)?;
        let context = decision
            .context
            .map(|handle| read_text(reader, handle, "context", decision.id))
            .transpose()?;
        let (fragment, _) = capability::decision_fragment(
            decision.id,
            title,
            context,
            decision.about,
            decision.created_at,
        )?;
        commits[commit_index[&source]].content += fragment;
    }

    let mut built_factors = Vec::new();
    for factor in catalog.factors.values() {
        let source = first_witness(authored, factor.id, metadata::name.id())?;
        let text = read_text(reader, factor.text, "factor text", factor.id)?;
        let (fragment, id) = capability::factor_fragment(
            factor.id,
            factor.decision,
            factor.side,
            text,
            factor.created_at,
        )?;
        commits[commit_index[&source]].content += fragment;
        built_factors.push(BuiltFactor {
            id,
            decision: factor.decision,
            side: factor.side,
            source_commit: source.commit.raw,
        });
    }

    let mut built_resolutions = Vec::new();
    for occurrence in occurrences {
        let ancestors = &closure[&occurrence.source.commit.raw];
        let evidence: Vec<Id> = built_factors
            .iter()
            .filter(|factor| {
                factor.decision == occurrence.decision && ancestors.contains(&factor.source_commit)
            })
            .map(|factor| factor.id)
            .collect();
        let has_pro = built_factors.iter().any(|factor| {
            factor.decision == occurrence.decision
                && factor.side == FactorSide::Pro
                && ancestors.contains(&factor.source_commit)
        });
        let has_con = built_factors.iter().any(|factor| {
            factor.decision == occurrence.decision
                && factor.side == FactorSide::Con
                && ancestors.contains(&factor.source_commit)
        });
        // The legacy writer deliberately did not record its bypass flag. Its
        // published semantics defined missing-sided evidence as the trace of a
        // forced resolution; with both sides present the bypass was
        // observationally redundant and the canonical reconstruction is false.
        let forced = !(has_pro && has_con);
        let predecessors = maximal_resolution_predecessors(
            occurrence.decision,
            occurrence.source.commit.raw,
            &built_resolutions,
            &closure,
        )?;
        let outcome = read_text(
            reader,
            occurrence.outcome,
            "resolution outcome",
            occurrence.decision,
        )?;
        let (fragment, id) = capability::resolution_fragment(
            occurrence.decision,
            outcome,
            // Pre-cutover resolutions predate the machine-readable result tag
            // and carry outcome prose only. Inventing one here would forge a
            // judgement nobody made.
            None,
            forced,
            &evidence,
            &predecessors,
            occurrence.finished_at,
        )?;
        commits[commit_index[&occurrence.source]].content += fragment;
        built_resolutions.push(BuiltResolution {
            id,
            decision: occurrence.decision,
            source_commit: occurrence.source.commit.raw,
        });
    }

    let mut content = Fragment::empty();
    for commit in &commits {
        content += commit.content.clone();
    }
    capability::validate_catalog_union(reader, &TribleSet::new(), &content)
        .context("validate reconstructed Decide catalog and staged payloads")?;

    let report = DecideRewriteReport {
        authored_commits: authored.len(),
        authored_empty_commits: authored
            .iter()
            .filter(|commit| commit.content.facts().is_empty())
            .count(),
        contentless_merges: branch
            .deltas
            .iter()
            .filter(|delta| !delta.is_authored())
            .count(),
        legacy_decisions: catalog.decisions.len(),
        canonical_factors: built_factors.len(),
        canonical_resolutions: built_resolutions.len(),
        input_unique_facts: source_facts.len(),
        output_facts: content.facts().len(),
    };
    Ok(PartitionedDecideRewrite {
        content,
        commits,
        report,
    })
}

/// Plan the complete legacy Decide branch without mutating either pile.
pub fn plan(source: &FrozenSource) -> Result<DecideMigrationPlan> {
    let branch = source
        .legacy_branch(LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Decide branch"))?;
    let projected = project_legacy_authored_commits(source, &branch, validate_legacy_payloads)
        .context("project frozen Decide authored commits")?;
    let original: TribleSet = projected
        .iter()
        .flat_map(|commit| commit.content.facts().iter().copied())
        .collect();
    let rewritten = rewrite_decide_authored_commits(&branch, &projected, source.reader())
        .context("reconstruct collection-native Decide DAG")?;

    let mut commits = Vec::with_capacity(rewritten.commits.len());
    for mut partition in rewritten.commits {
        let mut preserved = partition.preserved;
        preserved.describe_with(partition.metadata.clone());
        partition.content.describe_with(partition.metadata);
        commits.push(DecideMigrationCommit {
            source: partition.source,
            fragment: partition.content,
            preserved,
        });
    }
    let materialized: TribleSet = commits
        .iter()
        .flat_map(|commit| commit.fragment.facts().iter().copied())
        .collect();
    let additions = materialized.difference(&original);
    let plan = DecideMigrationPlan {
        source_pin: branch.pin_coordinate(),
        commits,
        original,
        additions,
        report: rewritten.report,
    };
    plan.validate(source.reader())?;
    Ok(plan)
}

/// Publish a frozen plan through the native collection facade.
pub fn publish(
    source: &FrozenSource,
    plan: &DecideMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Decide migration plan does not belong to this frozen source");
    }
    plan.validate(source.reader())?;
    publish_fragments(
        target,
        key,
        schema::DEFAULT_SCOPE_ID,
        plan.commits.iter().map(|commit| commit.fragment.clone()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::path::PathBuf;

    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use triblespace::core::collection::Collection;
    use triblespace::core::repo::Repository;
    use triblespace::macros::entity;
    use triblespace::prelude::{ufoid, BlobStore, ExclusiveId, TryToInline};

    use crate::collection_cutover::{freeze_source};
use faculties::storage::{discover_target, initialize_signer, load_signer, open_pile_strict};

    struct Fixture {
        _directory: tempfile::TempDir,
        source: PathBuf,
        destination: PathBuf,
        key: PathBuf,
        decision: Id,
    }

    fn at(seconds: f64) -> IntervalValue {
        let instant = Epoch::from_tai_seconds(seconds);
        (instant, instant).try_to_inline().unwrap()
    }

    fn kinds(fragment: &mut Fragment) {
        for (kind, label) in [
            (KIND_DECISION, "decide-decision"),
            (KIND_PRO, "decide-pro"),
            (KIND_CON, "decide-con"),
        ] {
            let name = fragment.put(label.to_owned());
            *fragment += entity! { ExclusiveId::force_ref(&kind) @ metadata::name: name };
        }
    }

    fn proposal(decision: Id, title: &str) -> Fragment {
        let mut fragment = Fragment::empty();
        kinds(&mut fragment);
        let title = fragment.put(title.to_owned());
        fragment += entity! { ExclusiveId::force_ref(&decision) @
            metadata::tag: &KIND_DECISION,
            metadata::name: title,
            metadata::created_at: at(1.0),
        };
        fragment
    }

    fn legacy_factor(decision: Id, side: FactorSide, text: &str, when: f64) -> Fragment {
        let mut fragment = Fragment::empty();
        let text = fragment.put(text.to_owned());
        let kind = side.kind();
        fragment += entity! { ufoid() @
            metadata::tag: &kind,
            metadata::name: text,
            metadata::created_at: at(when),
            factor::about_decision: &decision,
        };
        fragment
    }

    fn resolution(decision: Id, outcome: &str, when: f64) -> Fragment {
        let mut fragment = Fragment::empty();
        let outcome = fragment.put(outcome.to_owned());
        fragment += entity! { ExclusiveId::force_ref(&decision) @
            decide::outcome: outcome,
            metadata::finished_at: at(when),
        };
        fragment
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("legacy.pile");
        let destination = directory.path().join("candidate.pile");
        let key = directory.path().join("candidate.key");
        File::create(&source).unwrap();
        File::create(&destination).unwrap();
        let storage = open_pile_strict(&source).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0x91; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository.create_branch(LEGACY_BRANCH_NAME, None).unwrap();
        let decision = Id::new([0x92; 16]).unwrap();

        let mut root = repository.pull(branch).unwrap();
        root.commit(proposal(decision, "choose"), "proposal");
        repository.push(&mut root).unwrap();

        let mut left = repository.pull(branch).unwrap();
        let mut right = repository.pull(branch).unwrap();
        left.commit(
            legacy_factor(decision, FactorSide::Pro, "benefit", 2.0),
            "pro fork",
        );
        right.commit(
            legacy_factor(decision, FactorSide::Con, "risk", 3.0),
            "con fork",
        );
        repository.push(&mut left).unwrap();
        repository.push(&mut right).unwrap();

        let mut joined = repository.pull(branch).unwrap();
        joined.commit(resolution(decision, "proceed", 4.0), "joined resolution");
        repository.push(&mut joined).unwrap();
        let mut empty = repository.pull(branch).unwrap();
        empty.commit(Fragment::empty(), "authored empty");
        repository.push(&mut empty).unwrap();
        repository.close().unwrap();
        initialize_signer(&destination, Some(&key)).unwrap();
        Fixture {
            _directory: directory,
            source,
            destination,
            key,
            decision,
        }
    }

    struct TestView {
        facts: TribleSet,
        reader: PileReader,
        commits: usize,
    }

    fn materialized(fixture: &Fixture) -> TestView {
        let signer = load_signer(&fixture.destination, Some(&fixture.key)).unwrap();
        let mut pile = open_pile_strict(&fixture.destination).unwrap();
        let commits = discover_target(&mut pile, schema::DEFAULT_SCOPE_ID, signer.verifying_key())
            .unwrap()
            .commits()
            .len();
        let mut collection = faculties::collection_names::open(pile, schema::DEFAULT_SCOPE_ID, signer);
        let facts = collection.materialize().unwrap();
        let reader = collection.storage_mut().reader().unwrap();
        collection.into_storage().close().unwrap();
        TestView {
            facts,
            reader,
            commits,
        }
    }

    #[test]
    fn repository_ancestry_recovers_evidence_and_preserves_authored_empty() {
        let fixture = fixture();
        let source = freeze_source(&fixture.source).unwrap();
        let planned = plan(&source).unwrap();
        assert_eq!(planned.commits().len(), 5);
        assert_eq!(planned.report().authored_empty_commits, 1);
        planned.verify_conservation().unwrap();
        publish(&source, &planned, &fixture.destination, Some(&fixture.key)).unwrap();
        let view = materialized(&fixture);
        capability::validate_catalog(&view.reader, &view.facts).unwrap();
        assert!(planned
            .original_facts()
            .iter()
            .all(|fact| view.facts.contains(fact)));
        let factors = capability::factors_for_decision(&view.facts, fixture.decision).unwrap();
        assert_eq!(factors.len(), 2);
        match capability::resolution(&view.facts, fixture.decision) {
            capability::Resolution::Unique(snapshot) => {
                assert!(!snapshot.forced);
                assert_eq!(snapshot.evidence.len(), 2);
                assert!(snapshot.predecessors.is_empty());
            }
            other => panic!("unexpected resolution: {other:?}"),
        }
        assert_eq!(view.commits, 5);
    }

    #[test]
    fn exact_replay_is_idempotent_in_the_fixed_decide_collection() {
        let fixture = fixture();
        let source = freeze_source(&fixture.source).unwrap();
        let planned = plan(&source).unwrap();
        let first = publish(&source, &planned, &fixture.destination, Some(&fixture.key)).unwrap();
        let second = publish(&source, &planned, &fixture.destination, Some(&fixture.key)).unwrap();
        assert_eq!(first, second);
        assert_eq!(materialized(&fixture).commits, planned.commits().len());
    }

    #[test]
    fn split_resolution_pair_fails_closed_before_candidate_creation() {
        let fixture = fixture();
        let storage = open_pile_strict(&fixture.source).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0x94; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = repository.ensure_branch(LEGACY_BRANCH_NAME, None).unwrap();
        let mut workspace = repository.pull(branch).unwrap();
        workspace.commit(
            entity! { ExclusiveId::force_ref(&fixture.decision) @
                metadata::finished_at: at(9.0)
            },
            "malformed split finish",
        );
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();
        let frozen = freeze_source(&fixture.source).unwrap();
        let error = plan(&frozen).unwrap_err();
        assert!(format!("{error:#}").contains("pairing is ambiguous"));
        assert_eq!(std::fs::metadata(&fixture.destination).unwrap().len(), 0);
    }
}
