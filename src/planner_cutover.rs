//! Strictly additive stopped-world migration of the legacy Planner branch.
//!
//! Legacy Planner used randomly minted event and note entities and represented
//! a later local cancellation by appending another `event::status` fact. The
//! native ontology derives event identity from the exact iCalendar UID, derives
//! note identity from its complete semantic record, and models cancellation as
//! an intrinsic monotone assertion.
//!
//! This planner never rewrites or drops historical data. Every authored legacy
//! commit remains one independent collection commit with its exact content
//! fragment, semantic metadata, exports, metafacts, blob closure, and entity
//! ids. Canonical event, note, and cancellation records are added as shadows;
//! only shadow facts absent from the complete legacy union are emitted. The
//! target law is therefore exactly `legacy facts ∪ genuinely new shadows`.
//! Contentless repository merges remain verified ancestry and never acquire
//! collection authority.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use hifitime::Epoch;
use triblespace::core::attribute::Attribute;
use triblespace::core::blob::encodings::longstring::LongString;
use triblespace::core::blob::Blob;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::shortstring::ShortString;
use triblespace::core::inline::{Inline, InlineEncoding, TryToInline};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::BlobStoreGet;
use triblespace::core::trible::{Fragment, Trible, TribleSet};
use triblespace::macros::{find, pattern};
use triblespace::prelude::inlineencodings;

use crate::collection_cutover::{
    project_legacy_authored_commits, publish_fragments, FrozenLegacyBranch, FrozenSource,
    LegacyCommitCoordinate, LegacyPinCoordinate, ProjectedLegacyCommit,
};
use crate::planner::{self, EventDraft, IntervalValue, STATUS_CANCELLED};
use crate::schemas::planner::{
    event, note, DEFAULT_SCOPE_ID, KIND_EVENT_ID, KIND_NOTE_ID, LEGACY_BRANCH_NAME,
};

/// One native collection commit corresponding to one exact authored legacy
/// commit.
///
/// The original content and metadata remain separately inspectable so callers
/// can audit preservation without reverse-engineering the combined publication
/// fragment. `additions` contains only facts absent from the full legacy union.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannerMigrationCommit {
    pub source: LegacyCommitCoordinate,
    legacy: Fragment,
    metadata: Fragment,
    additions: Fragment,
    fragment: Fragment,
}

impl PlannerMigrationCommit {
    /// Exact projected content of the authored legacy commit.
    pub fn legacy_content(&self) -> &Fragment {
        &self.legacy
    }

    /// Exact projected semantic metadata of the authored legacy commit.
    pub fn legacy_metadata(&self) -> &Fragment {
        &self.metadata
    }

    /// Genuinely new canonical shadow content assigned to this commit.
    pub fn additions(&self) -> &Fragment {
        &self.additions
    }

    /// Complete self-contained fragment passed to `Collection::commit`.
    pub fn fragment(&self) -> &Fragment {
        &self.fragment
    }
}

/// Explicit census for one complete stopped-world Planner plan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PlannerMigrationReport {
    pub authored_commits: usize,
    pub authored_empty_commits: usize,
    pub contentless_merges: usize,
    pub legacy_fact_occurrences: usize,
    pub legacy_metafact_occurrences: usize,
    pub legacy_export_occurrences: usize,
    pub legacy_blob_occurrences: usize,
    pub preserved_facts: usize,
    pub shadow_facts: usize,
    pub overlapping_shadow_facts: usize,
    pub added_facts: usize,
    pub output_facts: usize,
    pub legacy_events: usize,
    pub canonical_events: usize,
    pub legacy_notes: usize,
    pub canonical_notes: usize,
    pub legacy_cancellation_occurrences: usize,
    pub canonical_cancellations: usize,
    pub redundant_occurrences: usize,
}

/// Pure stopped-world plan ready for native collection publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannerMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<PlannerMigrationCommit>,
    original: TribleSet,
    shadows: TribleSet,
    additions: TribleSet,
    event_ids: BTreeMap<Id, Id>,
    note_ids: BTreeMap<Id, Id>,
    report: PlannerMigrationReport,
}

impl PlannerMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[PlannerMigrationCommit] {
        &self.commits
    }

    /// Set union of the exact facts found in authored legacy commits.
    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    /// Full canonical semantic shadow, including facts already present in the
    /// legacy union.
    pub fn shadow_facts(&self) -> &TribleSet {
        &self.shadows
    }

    /// Exact shadow difference emitted by the plan.
    pub fn added_facts(&self) -> &TribleSet {
        &self.additions
    }

    /// Legacy random event id to canonical UID-derived event id.
    pub fn event_ids(&self) -> &BTreeMap<Id, Id> {
        &self.event_ids
    }

    /// Legacy random note id to canonical intrinsic note id.
    pub fn note_ids(&self) -> &BTreeMap<Id, Id> {
        &self.note_ids
    }

    pub const fn report(&self) -> &PlannerMigrationReport {
        &self.report
    }

    /// Union the ordinary facts of every planned collection commit.
    pub fn materialized_facts(&self) -> TribleSet {
        let mut facts = TribleSet::new();
        for commit in &self.commits {
            facts += commit.fragment.facts().clone();
        }
        facts
    }

    /// Recheck exact authored-fragment preservation and the additive target
    /// equation without consulting either source or destination storage.
    pub fn verify_conservation(&self) -> Result<()> {
        let mut observed_original = TribleSet::new();
        let mut observed_additions = TribleSet::new();
        for commit in &self.commits {
            verify_commit_preservation(commit)?;
            observed_original += commit.legacy.facts().clone();
            for fact in commit.additions.facts() {
                if self.original.contains(fact) {
                    bail!("Planner migration classifies an existing legacy fact as an addition");
                }
                let occurrences = self
                    .commits
                    .iter()
                    .filter(|candidate| candidate.additions.facts().contains(fact))
                    .count();
                if occurrences != 1 {
                    bail!(
                        "additive Planner fact is assigned to {occurrences} authored commits; expected exactly one"
                    );
                }
            }
            observed_additions += commit.additions.facts().clone();
        }
        if observed_original != self.original {
            bail!("Planner plan's preserved authored facts differ from its original-facts census");
        }
        if observed_additions != self.additions {
            bail!("Planner plan's assigned additions differ from its added-facts census");
        }
        if self.additions != self.shadows.difference(&self.original) {
            bail!("Planner additions are not exactly canonical shadows minus legacy facts");
        }
        let mut expected = self.original.clone();
        expected += self.additions.clone();
        if self.materialized_facts() != expected {
            bail!("planned Planner collection is not exactly legacy facts union additive shadows");
        }
        Ok(())
    }

    fn validate(&self, reader: &PileReader) -> Result<()> {
        self.verify_conservation()?;
        let mut complete = Fragment::empty();
        for commit in &self.commits {
            complete += commit.fragment.clone();
        }
        let catalog = planner::validate_candidate(reader, &TribleSet::new(), &complete)
            .context("validate planned additive Planner collection and attachments")?;
        let event_count = self
            .event_ids
            .values()
            .copied()
            .collect::<BTreeSet<_>>()
            .len();
        let note_count = self
            .note_ids
            .values()
            .copied()
            .collect::<BTreeSet<_>>()
            .len();
        if catalog.events.len() != event_count {
            bail!("Planner canonical event conservation failed");
        }
        if catalog.notes.len() != note_count {
            bail!("Planner canonical note conservation failed");
        }
        if catalog.cancellations.len() != self.report.canonical_cancellations {
            bail!("Planner canonical cancellation conservation failed");
        }
        Ok(())
    }
}

/// Plan the complete named legacy Planner branch without mutating its pile.
pub fn plan(source: &FrozenSource) -> Result<PlannerMigrationPlan> {
    let branch = source
        .legacy_branch(LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Planner branch"))?;
    let projected = project_legacy_authored_commits(source, &branch, validate_legacy_payloads)
        .context("project frozen Planner authored commits")?;
    plan_projected(&branch, projected, source.reader())
}

/// Publish a verified plan through the direct native collection facade.
///
/// Callers must keep every legacy Planner writer stopped from [`FrozenSource`]
/// creation through publication. Exact replay, including in-place replay, is
/// content-addressed and idempotent.
pub fn publish(
    source: &FrozenSource,
    plan: &PlannerMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Planner migration plan does not belong to this frozen source");
    }
    plan.validate(source.reader())?;
    publish_fragments(
        target,
        key,
        DEFAULT_SCOPE_ID,
        plan.commits.iter().map(|commit| commit.fragment.clone()),
    )
}

fn verify_commit_preservation(commit: &PlannerMigrationCommit) -> Result<()> {
    let mut expected_facts = commit.legacy.facts().clone();
    expected_facts += commit.additions.facts().clone();
    if commit.fragment.facts() != &expected_facts {
        bail!(
            "Planner output commit {} changes its authored content facts",
            hex::encode_upper(commit.source.commit.raw)
        );
    }

    let mut expected_metafacts = commit.legacy.metafacts().clone();
    expected_metafacts += commit.additions.metafacts().clone();
    expected_metafacts += commit.metadata.facts().clone();
    expected_metafacts += commit.metadata.metafacts().clone();
    if commit.fragment.metafacts() != &expected_metafacts {
        bail!(
            "Planner output commit {} changes authored or semantic metafacts",
            hex::encode_upper(commit.source.commit.raw)
        );
    }

    let mut expected_exports: BTreeSet<_> = commit.legacy.exports().collect();
    expected_exports.extend(commit.additions.exports());
    let actual_exports: BTreeSet<_> = commit.fragment.exports().collect();
    if actual_exports != expected_exports {
        bail!(
            "Planner output commit {} changes authored exports",
            hex::encode_upper(commit.source.commit.raw)
        );
    }

    let mut expected_blobs = commit.legacy.blobs().clone();
    expected_blobs.union(commit.additions.blobs().clone());
    expected_blobs.union(commit.metadata.blobs().clone());
    if commit.fragment.blobs() != &expected_blobs {
        bail!(
            "Planner output commit {} changes authored attachment closure",
            hex::encode_upper(commit.source.commit.raw)
        );
    }
    Ok(())
}

fn plan_projected(
    branch: &FrozenLegacyBranch,
    mut projected: Vec<ProjectedLegacyCommit>,
    reader: &PileReader,
) -> Result<PlannerMigrationPlan> {
    projected.sort_unstable_by_key(|commit| commit.source);
    for pair in projected.windows(2) {
        if pair[0].source == pair[1].source {
            bail!(
                "Planner input repeats legacy authored commit {}",
                hex::encode_upper(pair[0].source.commit.raw)
            );
        }
    }

    let source_pin = branch.pin_coordinate();
    let expected_sources: BTreeSet<LegacyCommitCoordinate> = branch
        .deltas
        .iter()
        .filter(|delta| delta.is_authored())
        .map(|delta| LegacyCommitCoordinate {
            branch: branch.branch,
            pin: branch.pin,
            commit: delta.commit,
        })
        .collect();
    let actual_sources: BTreeSet<_> = projected.iter().map(|commit| commit.source).collect();
    if actual_sources != expected_sources {
        bail!(
            "Planner authored commits do not exactly cover the frozen branch (expected {}, found {})",
            expected_sources.len(),
            actual_sources.len()
        );
    }
    if projected.iter().any(|commit| {
        commit.source.branch != source_pin.id || commit.source.pin != source_pin.value
    }) {
        bail!("Planner authored commits do not belong to one frozen branch pin");
    }

    let parents = validate_branch_dag(branch)?;
    let commit_by_source: BTreeMap<_, _> = projected
        .iter()
        .map(|commit| (commit.source, commit))
        .collect();
    let mut original = TribleSet::new();
    for commit in &projected {
        original += commit.content.facts().clone();
    }

    let event_entities = tagged_entities(&original, KIND_EVENT_ID);
    let note_entities = tagged_entities(&original, KIND_NOTE_ID);
    if let Some(id) = event_entities.intersection(&note_entities).next() {
        bail!("legacy Planner entity {id:X} is both an event and a note");
    }

    let mut event_genesis = BTreeMap::new();
    for old_event in &event_entities {
        let candidates = tag_sources(&projected, *old_event, KIND_EVENT_ID);
        let source = unique_causal_genesis("event", *old_event, &candidates, &parents)?;
        event_genesis.insert(*old_event, source);
    }
    let mut note_genesis = BTreeMap::new();
    for old_note in &note_entities {
        let candidates = tag_sources(&projected, *old_note, KIND_NOTE_ID);
        let source = unique_causal_genesis("note", *old_note, &candidates, &parents)?;
        note_genesis.insert(*old_note, source);
    }

    validate_legacy_vocabulary(reader, &original)?;
    let mut cancellation_sources = BTreeMap::<Id, BTreeSet<LegacyCommitCoordinate>>::new();
    let mut redundant_occurrences = 0;
    for commit in &projected {
        for fact in commit.content.facts() {
            let subject = *fact.e();
            if let Some(genesis) = event_genesis.get(&subject).copied() {
                require_event_attribute(fact)?;
                if commit.source == genesis {
                    continue;
                }
                let genesis_facts = commit_by_source[&genesis].content.facts();
                if genesis_facts.contains(fact) {
                    require_descendant(
                        commit.source,
                        genesis,
                        &parents,
                        "redundant Planner event assertion",
                    )?;
                    redundant_occurrences += 1;
                    continue;
                }
                if fact.a() == &event::status.id()
                    && short_value(fact, "legacy event status")? == STATUS_CANCELLED
                {
                    require_descendant(commit.source, genesis, &parents, "Planner cancellation")?;
                    cancellation_sources
                        .entry(subject)
                        .or_default()
                        .insert(commit.source);
                    continue;
                }
                bail!(
                    "legacy Planner event {subject:X} has a post-genesis assertion for attribute {:X}",
                    fact.a()
                );
            }

            if let Some(genesis) = note_genesis.get(&subject).copied() {
                require_note_attribute(fact)?;
                if commit.source == genesis {
                    continue;
                }
                let genesis_facts = commit_by_source[&genesis].content.facts();
                if genesis_facts.contains(fact) {
                    require_descendant(
                        commit.source,
                        genesis,
                        &parents,
                        "redundant Planner note assertion",
                    )?;
                    redundant_occurrences += 1;
                    continue;
                }
                bail!(
                    "legacy Planner note {subject:X} has a post-genesis assertion for attribute {:X}",
                    fact.a()
                );
            }

            if (subject == KIND_EVENT_ID || subject == KIND_NOTE_ID)
                && fact.a() == &metadata::name.id()
            {
                continue;
            }
            bail!(
                "legacy Planner fact on unknown subject {subject:X} attribute {:X}",
                fact.a()
            );
        }
    }

    let mut shadow_records = Vec::<(LegacyCommitCoordinate, Id, Fragment)>::new();
    let mut event_ids = BTreeMap::new();
    let mut uid_owners = BTreeMap::<String, Id>::new();
    for old_event in &event_entities {
        let genesis = event_genesis[old_event];
        let facts = entity_facts(commit_by_source[&genesis].content.facts(), *old_event);
        let draft = load_legacy_event(reader, *old_event, &facts)?;
        if let Some(existing) = uid_owners.insert(draft.uid.clone(), *old_event) {
            bail!(
                "legacy Planner events {existing:X} and {old_event:X} share UID {:?}",
                draft.uid
            );
        }
        let canonical = planner::event_fragment(&draft)
            .with_context(|| format!("rebuild legacy Planner event {old_event:X}"))?;
        let new_event = canonical
            .root()
            .expect("canonical Planner event has one root");
        event_ids.insert(*old_event, new_event);
        shadow_records.push((genesis, new_event, canonical));
    }

    let mut note_ids = BTreeMap::new();
    let mut canonical_notes = BTreeMap::<Id, (Fragment, BTreeSet<LegacyCommitCoordinate>)>::new();
    for old_note in &note_entities {
        let genesis = note_genesis[old_note];
        let facts = entity_facts(commit_by_source[&genesis].content.facts(), *old_note);
        let legacy = load_legacy_note(reader, *old_note, &facts)?;
        let event_source = event_genesis.get(&legacy.event).copied().ok_or_else(|| {
            anyhow!(
                "legacy Planner note {old_note:X} refers to missing event {:X}",
                legacy.event
            )
        })?;
        require_descendant(genesis, event_source, &parents, "Planner note reference")?;
        let new_event = event_ids[&legacy.event];
        let canonical = planner::note_fragment(new_event, &legacy.text, legacy.created_at)
            .with_context(|| format!("rebuild legacy Planner note {old_note:X}"))?;
        let new_note = canonical
            .root()
            .expect("canonical Planner note has one root");
        note_ids.insert(*old_note, new_note);
        match canonical_notes.entry(new_note) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((canonical, BTreeSet::from([genesis])));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if entry.get().0.facts() != canonical.facts() {
                    bail!("intrinsic Planner note id collision at {new_note:X}");
                }
                entry.get_mut().1.insert(genesis);
            }
        }
    }
    for (new_note, (canonical, owners)) in canonical_notes {
        let owner = earliest_causal_owner(&owners, &parents)
            .expect("a canonical note owner set is nonempty");
        shadow_records.push((owner, new_note, canonical));
    }

    for (old_event, sources) in &cancellation_sources {
        let owner = earliest_causal_owner(sources, &parents)
            .expect("a cancellation source set is nonempty");
        let new_event = event_ids[old_event];
        let canonical = planner::cancellation_fragment(new_event);
        let cancellation = canonical
            .root()
            .expect("canonical Planner cancellation has one root");
        shadow_records.push((owner, cancellation, canonical));
    }

    // Stable record order makes addition ownership independent of hash-map,
    // branch traversal, and caller input order. Every emitted fact is removed
    // from the complete legacy union and claimed by at most one source.
    shadow_records.sort_unstable_by_key(|(owner, root, _)| (*owner, *root));
    let mut shadows = TribleSet::new();
    let mut additions = TribleSet::new();
    let mut additions_by_source = BTreeMap::<LegacyCommitCoordinate, Fragment>::new();
    for (owner, _root, shadow) in shadow_records {
        shadows += shadow.facts().clone();
        let missing = shadow.facts().difference(&original).difference(&additions);
        if missing.is_empty() {
            continue;
        }
        additions += missing.clone();
        *additions_by_source
            .entry(owner)
            .or_insert_with(Fragment::empty) += shadow_subset(&shadow, missing);
    }
    let expected_additions = shadows.difference(&original);
    if additions != expected_additions {
        bail!("Planner shadow partition did not claim every genuinely new fact exactly once");
    }

    let authored_empty_commits = projected
        .iter()
        .filter(|commit| commit.content.facts().is_empty())
        .count();
    let legacy_fact_occurrences = projected
        .iter()
        .map(|commit| commit.content.facts().len())
        .sum();
    let legacy_metafact_occurrences = projected
        .iter()
        .map(|commit| commit.content.metafacts().len())
        .sum();
    let legacy_export_occurrences = projected
        .iter()
        .map(|commit| commit.content.exports().count())
        .sum();
    let legacy_blob_occurrences = projected
        .iter()
        .map(|commit| commit.content.blobs().len())
        .sum();

    let mut commits = Vec::with_capacity(projected.len());
    for projected in projected {
        let legacy = projected.content;
        let metadata = projected.metadata;
        let additions = additions_by_source
            .remove(&projected.source)
            .unwrap_or_else(Fragment::empty);
        let mut fragment = legacy.clone();
        fragment += additions.clone();
        fragment.describe_with(metadata.clone());
        commits.push(PlannerMigrationCommit {
            source: projected.source,
            legacy,
            metadata,
            additions,
            fragment,
        });
    }
    if !additions_by_source.is_empty() {
        bail!("Planner shadow partition names a non-input source coordinate");
    }

    let mut output = TribleSet::new();
    for commit in &commits {
        output += commit.fragment.facts().clone();
    }
    let canonical_event_count = event_ids.values().copied().collect::<BTreeSet<_>>().len();
    let canonical_note_count = note_ids.values().copied().collect::<BTreeSet<_>>().len();
    let report = PlannerMigrationReport {
        authored_commits: commits.len(),
        authored_empty_commits,
        contentless_merges: branch
            .deltas
            .iter()
            .filter(|delta| !delta.is_authored())
            .count(),
        legacy_fact_occurrences,
        legacy_metafact_occurrences,
        legacy_export_occurrences,
        legacy_blob_occurrences,
        preserved_facts: original.len(),
        shadow_facts: shadows.len(),
        overlapping_shadow_facts: shadows.intersect(&original).len(),
        added_facts: additions.len(),
        output_facts: output.len(),
        legacy_events: event_entities.len(),
        canonical_events: canonical_event_count,
        legacy_notes: note_entities.len(),
        canonical_notes: canonical_note_count,
        legacy_cancellation_occurrences: cancellation_sources.values().map(BTreeSet::len).sum(),
        canonical_cancellations: cancellation_sources.len(),
        redundant_occurrences,
    };
    let plan = PlannerMigrationPlan {
        source_pin,
        commits,
        original,
        shadows,
        additions,
        event_ids,
        note_ids,
        report,
    };
    plan.validate(reader)?;
    Ok(plan)
}

fn shadow_subset(shadow: &Fragment, facts: TribleSet) -> Fragment {
    let mut subset = Fragment::new(shadow.exports(), facts);
    *subset.metafacts_mut() += shadow.metafacts().clone();
    subset.blobs_mut().union(shadow.blobs().clone());
    subset
}

/// Select a deterministic first causal witness. A descendant can never win
/// merely because its content hash sorts earlier; concurrent equivalent first
/// witnesses use their exact source coordinate as the final stable tie-break.
fn earliest_causal_owner(
    candidates: &BTreeSet<LegacyCommitCoordinate>,
    parents: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
) -> Option<LegacyCommitCoordinate> {
    candidates
        .iter()
        .copied()
        .filter(|candidate| {
            !candidates.iter().any(|other| {
                other != candidate && is_descendant(candidate.commit.raw, other.commit.raw, parents)
            })
        })
        .min()
}

#[derive(Clone, Debug)]
struct LegacyNote {
    event: Id,
    text: String,
    created_at: IntervalValue,
}

fn load_legacy_event(reader: &PileReader, id: Id, facts: &TribleSet) -> Result<EventDraft> {
    require_exact_tag(facts, id, KIND_EVENT_ID, "event")?;
    let created_at = exactly_one(
        id,
        "metadata::created_at",
        inline_values(facts, id, &metadata::created_at),
    )?;
    // Historical Planner sampled the clock twice when constructing this
    // interval. It is preserved verbatim on the legacy entity and does not
    // participate in the canonical event record, so only validate that it is
    // a well-formed interval; requiring equal endpoints would reject valid
    // data produced by the original writer.
    decode_legacy_interval(id, "legacy event creation time", created_at)?;
    let uid = exactly_one(
        id,
        "event::ical_uid",
        inline_values(facts, id, &event::ical_uid),
    )?;
    let uid = planner::read_text(reader, uid)
        .with_context(|| format!("read UID of legacy Planner event {id:X}"))?;
    let description = at_most_one(
        id,
        "event::description",
        inline_values(facts, id, &event::description),
    )?
    .map(|handle| planner::read_text(reader, handle))
    .transpose()
    .with_context(|| format!("read description of legacy Planner event {id:X}"))?;
    Ok(EventDraft {
        uid,
        summary: exactly_one(
            id,
            "event::summary",
            short_values(facts, id, &event::summary)?,
        )?,
        description,
        time: exactly_one(id, "event::time", inline_values(facts, id, &event::time))?,
        rrule: at_most_one(id, "event::rrule", short_values(facts, id, &event::rrule)?)?,
        rdates: inline_values(facts, id, &event::rdate)
            .into_iter()
            .collect(),
        exdates: inline_values(facts, id, &event::exdate)
            .into_iter()
            .collect(),
        location: at_most_one(
            id,
            "event::location",
            short_values(facts, id, &event::location)?,
        )?,
        status: exactly_one(
            id,
            "event::status",
            short_values(facts, id, &event::status)?,
        )?,
        transp: exactly_one(
            id,
            "event::transp",
            short_values(facts, id, &event::transp)?,
        )?,
        attendees: genid_values(facts, id, &event::attendee)?,
        organizer: at_most_one(
            id,
            "event::organizer",
            genid_values(facts, id, &event::organizer)?
                .into_iter()
                .collect(),
        )?,
        sequence: at_most_one(
            id,
            "event::sequence",
            inline_values(facts, id, &event::sequence),
        )?,
    })
}

fn load_legacy_note(reader: &PileReader, id: Id, facts: &TribleSet) -> Result<LegacyNote> {
    require_exact_tag(facts, id, KIND_NOTE_ID, "note")?;
    let created_at = exactly_one(
        id,
        "metadata::created_at",
        inline_values(facts, id, &metadata::created_at),
    )?;
    let created_at = legacy_creation_point(id, "legacy note creation time", created_at)?;
    let event = exactly_one(
        id,
        "note::note_about",
        genid_values(facts, id, &note::note_about)?
            .into_iter()
            .collect(),
    )?;
    let text = exactly_one(
        id,
        "note::note_text",
        inline_values(facts, id, &note::note_text),
    )?;
    let text = planner::read_text(reader, text)
        .with_context(|| format!("read text of legacy Planner note {id:X}"))?;
    Ok(LegacyNote {
        event,
        text,
        created_at,
    })
}

fn validate_branch_dag(branch: &FrozenLegacyBranch) -> Result<BTreeMap<[u8; 32], Vec<[u8; 32]>>> {
    let commits: BTreeSet<[u8; 32]> = branch.deltas.iter().map(|delta| delta.commit.raw).collect();
    if commits.len() != branch.deltas.len() {
        bail!("frozen Planner branch repeats a commit");
    }
    let mut parents = BTreeMap::new();
    for delta in &branch.deltas {
        let mut parent_ids: Vec<[u8; 32]> = delta.parents.iter().map(|parent| parent.raw).collect();
        parent_ids.sort_unstable();
        parent_ids.dedup();
        for parent in &parent_ids {
            if !commits.contains(parent) {
                bail!(
                    "frozen Planner commit {} names parent {} outside the branch closure",
                    hex::encode_upper(delta.commit.raw),
                    hex::encode_upper(parent)
                );
            }
        }
        parents.insert(delta.commit.raw, parent_ids);
    }
    Ok(parents)
}

fn is_descendant(
    descendant: [u8; 32],
    ancestor: [u8; 32],
    parents: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
) -> bool {
    let mut pending = vec![descendant];
    let mut seen = BTreeSet::new();
    while let Some(commit) = pending.pop() {
        if commit == ancestor {
            return true;
        }
        if !seen.insert(commit) {
            continue;
        }
        if let Some(next) = parents.get(&commit) {
            pending.extend(next.iter().copied());
        }
    }
    false
}

fn require_descendant(
    descendant: LegacyCommitCoordinate,
    ancestor: LegacyCommitCoordinate,
    parents: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    relation: &str,
) -> Result<()> {
    if !is_descendant(descendant.commit.raw, ancestor.commit.raw, parents) {
        bail!(
            "{relation} in commit {} is not descended from supporting commit {}",
            hex::encode_upper(descendant.commit.raw),
            hex::encode_upper(ancestor.commit.raw)
        );
    }
    Ok(())
}

fn unique_causal_genesis(
    kind: &str,
    entity: Id,
    candidates: &BTreeSet<LegacyCommitCoordinate>,
    parents: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
) -> Result<LegacyCommitCoordinate> {
    let minima: Vec<_> = candidates
        .iter()
        .copied()
        .filter(|candidate| {
            !candidates.iter().any(|other| {
                other != candidate && is_descendant(candidate.commit.raw, other.commit.raw, parents)
            })
        })
        .collect();
    match minima.as_slice() {
        [source] => Ok(*source),
        [] => bail!("legacy Planner {kind} {entity:X} has no genesis assertion"),
        _ => bail!(
            "legacy Planner {kind} {entity:X} has {} concurrent genesis assertions",
            minima.len()
        ),
    }
}

fn tag_sources(
    commits: &[ProjectedLegacyCommit],
    entity: Id,
    kind: Id,
) -> BTreeSet<LegacyCommitCoordinate> {
    commits
        .iter()
        .filter(|commit| {
            find!(
                value: Id,
                pattern!(commit.content.facts(), [{ entity @ metadata::tag: ?value }])
            )
            .any(|value| value == kind)
        })
        .map(|commit| commit.source)
        .collect()
}

fn tagged_entities(facts: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(
        entity: Id,
        pattern!(facts, [{ ?entity @ metadata::tag: kind }])
    )
    .collect()
}

fn entity_facts(facts: &TribleSet, entity: Id) -> TribleSet {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity)
        .copied()
        .collect()
}

fn require_event_attribute(fact: &Trible) -> Result<()> {
    let allowed = [
        metadata::tag.id(),
        metadata::created_at.id(),
        event::ical_uid.id(),
        event::summary.id(),
        event::description.id(),
        event::time.id(),
        event::rrule.id(),
        event::rdate.id(),
        event::exdate.id(),
        event::location.id(),
        event::status.id(),
        event::transp.id(),
        event::attendee.id(),
        event::organizer.id(),
        event::sequence.id(),
    ];
    if !allowed.contains(fact.a()) {
        bail!(
            "legacy Planner event {} has unknown attribute {:X}",
            fact.e(),
            fact.a()
        );
    }
    Ok(())
}

fn require_note_attribute(fact: &Trible) -> Result<()> {
    let allowed = [
        metadata::tag.id(),
        metadata::created_at.id(),
        note::note_about.id(),
        note::note_text.id(),
    ];
    if !allowed.contains(fact.a()) {
        bail!(
            "legacy Planner note {} has unknown attribute {:X}",
            fact.e(),
            fact.a()
        );
    }
    Ok(())
}

fn require_exact_tag(facts: &TribleSet, entity: Id, expected: Id, kind: &str) -> Result<()> {
    let values: BTreeSet<Id> = find!(
        value: Id,
        pattern!(facts, [{ entity @ metadata::tag: ?value }])
    )
    .collect();
    if values != BTreeSet::from([expected]) {
        bail!(
            "legacy Planner {kind} {entity:X} has tag set {:?}; expected only {expected:X}",
            values
        );
    }
    Ok(())
}

fn validate_legacy_vocabulary(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for kind in [KIND_EVENT_ID, KIND_NOTE_ID] {
        let names = inline_values(facts, kind, &metadata::name);
        if names.len() > 1 {
            bail!(
                "legacy Planner kind {kind:X} has {} names; expected at most one",
                names.len()
            );
        }
        if let Some(name) = names.first() {
            let _: View<str> = reader
                .get(*name)
                .with_context(|| format!("read legacy Planner kind name for {kind:X}"))?;
        }
        let all = entity_facts(facts, kind);
        if all.iter().any(|fact| fact.a() != &metadata::name.id()) {
            bail!("legacy Planner kind {kind:X} has non-name facts");
        }
    }
    Ok(())
}

fn validate_legacy_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts {
        if fact.a() == &metadata::name.id()
            || fact.a() == &metadata::description.id()
            || fact.a() == &event::ical_uid.id()
            || fact.a() == &event::description.id()
            || fact.a() == &note::note_text.id()
        {
            let handle = *fact.v::<inlineencodings::Handle<LongString>>();
            let _: Blob<LongString> = reader.get(handle).with_context(|| {
                format!(
                    "read frozen legacy Planner text {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
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

fn short_values(
    facts: &TribleSet,
    entity: Id,
    attribute: &Attribute<ShortString>,
) -> Result<Vec<String>> {
    inline_values(facts, entity, attribute)
        .into_iter()
        .map(|value| {
            value
                .try_from_inline()
                .map_err(|error| anyhow!("decode short Planner value: {error:?}"))
        })
        .collect()
}

fn genid_values(
    facts: &TribleSet,
    entity: Id,
    attribute: &Attribute<inlineencodings::GenId>,
) -> Result<BTreeSet<Id>> {
    inline_values(facts, entity, attribute)
        .into_iter()
        .map(|value| {
            value
                .try_from_inline()
                .map_err(|error| anyhow!("decode Planner GenId: {error:?}"))
        })
        .collect()
}

fn short_value(fact: &Trible, field: &str) -> Result<String> {
    (*fact.v::<ShortString>())
        .try_from_inline()
        .map_err(|error| anyhow!("decode {field}: {error:?}"))
}

fn exactly_one<T>(entity: Id, field: &str, mut values: Vec<T>) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "legacy Planner entity {entity:X} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(values.pop().expect("length checked"))
}

fn at_most_one<T>(entity: Id, field: &str, mut values: Vec<T>) -> Result<Option<T>> {
    if values.len() > 1 {
        bail!(
            "legacy Planner entity {entity:X} has {} values for {field}; expected at most one",
            values.len()
        );
    }
    Ok(values.pop())
}

fn decode_legacy_interval(
    entity: Id,
    field: &str,
    interval: IntervalValue,
) -> Result<(Epoch, Epoch)> {
    interval
        .try_from_inline()
        .map_err(|error| anyhow!("decode {field} on legacy Planner entity {entity:X}: {error:?}"))
}

fn legacy_creation_point(
    entity: Id,
    field: &str,
    interval: IntervalValue,
) -> Result<IntervalValue> {
    let (first_observation, _second_observation) = decode_legacy_interval(entity, field, interval)?;
    (first_observation, first_observation)
        .try_to_inline()
        .map_err(|error| {
            anyhow!("normalize {field} on legacy Planner entity {entity:X}: {error:?}")
        })
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use triblespace::core::repo::{BlobStore, BlobStoreMeta, PinStore, Repository};
    use triblespace::macros::{entity, id_hex};
    use triblespace::prelude::{ExclusiveId, TryToInline};

    use super::*;
    use crate::collection_cutover::{
        discover_target, freeze_source, initialize_signer, load_signer, open_pile_strict,
    };
    use crate::planner::{STATUS_CONFIRMED, TRANSP_OPAQUE};

    const OLD_EVENT_A: Id = id_hex!("B1000000000000000000000000000001");
    const OLD_EVENT_B: Id = id_hex!("B1000000000000000000000000000002");
    const OLD_NOTE_A: Id = id_hex!("B1000000000000000000000000000003");
    const OLD_NOTE_B: Id = id_hex!("B1000000000000000000000000000004");
    const METADATA_MARKER: Id = id_hex!("B1000000000000000000000000000005");
    const EXTRA_EXPORT: Id = id_hex!("B1000000000000000000000000000006");
    const EXTRA_META_ENTITY: Id = id_hex!("B1000000000000000000000000000007");

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-planner-cutover-{}-{serial}",
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

    fn at(seconds: f64) -> IntervalValue {
        let instant = Epoch::from_tai_seconds(seconds);
        (instant, instant).try_to_inline().unwrap()
    }

    fn span(start: f64, end: f64) -> IntervalValue {
        (Epoch::from_tai_seconds(start), Epoch::from_tai_seconds(end))
            .try_to_inline()
            .unwrap()
    }

    #[test]
    fn historical_double_clock_sample_projects_to_its_first_observation() {
        let historical = span(3.0, 3.000_001);
        decode_legacy_interval(OLD_EVENT_A, "event creation", historical).unwrap();
        assert_eq!(
            legacy_creation_point(OLD_NOTE_A, "note creation", historical).unwrap(),
            at(3.0)
        );
    }

    fn vocabulary() -> Fragment {
        let mut fragment = Fragment::empty();
        for (kind, label) in [
            (KIND_EVENT_ID, "planner-event"),
            (KIND_NOTE_ID, "planner-note"),
        ] {
            let label = fragment.put::<LongString, _>(label.to_owned());
            fragment += entity! { ExclusiveId::force_ref(&kind) @ metadata::name: label };
        }
        fragment
    }

    fn legacy_event(id: Id, uid: &str, status: &str, created_at: f64) -> Fragment {
        let mut fragment = Fragment::empty();
        let uid = fragment.put::<LongString, _>(uid.to_owned());
        let description = fragment.put::<LongString, _>(format!("description-{id:x}"));
        fragment += entity! { ExclusiveId::force_ref(&id) @
            metadata::tag: &KIND_EVENT_ID,
            metadata::created_at: at(created_at),
            event::ical_uid: uid,
            event::summary: if id == OLD_EVENT_A { "event-a" } else { "event-b" },
            event::description: description,
            event::time: span(created_at + 10.0, created_at + 20.0),
            event::status: status,
            event::transp: TRANSP_OPAQUE,
        };
        fragment
    }

    fn legacy_note(id: Id, event_id: Id, text: &str, created_at: f64) -> Fragment {
        let mut fragment = Fragment::empty();
        let text = fragment.put::<LongString, _>(text.to_owned());
        fragment += entity! { ExclusiveId::force_ref(&id) @
            metadata::tag: &KIND_NOTE_ID,
            metadata::created_at: at(created_at),
            note::note_about: &event_id,
            note::note_text: text,
        };
        fragment
    }

    fn legacy_cancellation(event_id: Id) -> Fragment {
        entity! { ExclusiveId::force_ref(&event_id) @ event::status: STATUS_CANCELLED }
    }

    struct Fixture {
        _directory: TestDirectory,
        source: std::path::PathBuf,
        destination: std::path::PathBuf,
        source_key: std::path::PathBuf,
        destination_key: std::path::PathBuf,
    }

    fn fixture(event_b_uid: &str) -> Fixture {
        let directory = TestDirectory::new();
        let source = directory.0.join("legacy.pile");
        let destination = directory.0.join("target.pile");
        let source_key = directory.0.join("source.key");
        let destination_key = directory.0.join("target.key");
        File::create(&source).unwrap();
        File::create(&destination).unwrap();

        let storage = open_pile_strict(&source).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0x51; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository.create_branch(LEGACY_BRANCH_NAME, None).unwrap();

        let mut root = repository.pull(branch).unwrap();
        root.commit(
            vocabulary()
                + legacy_event(OLD_EVENT_A, "uid-a", STATUS_CONFIRMED, 1.0)
                + legacy_event(OLD_EVENT_B, event_b_uid, STATUS_CANCELLED, 2.0),
            "root",
        );
        repository.push(&mut root).unwrap();

        let mut authored_empty = repository.pull(branch).unwrap();
        authored_empty.commit(Fragment::empty(), "authored empty");
        repository.push(&mut authored_empty).unwrap();

        let mut left = repository.pull(branch).unwrap();
        let mut right = repository.pull(branch).unwrap();
        let mut semantic_metadata = Fragment::empty();
        let detail = semantic_metadata.put::<LongString, _>("semantic provenance".to_owned());
        semantic_metadata += entity! {
            metadata::tag: &METADATA_MARKER,
            metadata::description: detail,
        };
        left.commit_with_metadata(
            legacy_note(OLD_NOTE_A, OLD_EVENT_A, "left note", 3.0),
            semantic_metadata,
            "left fork",
        );
        right.commit(
            legacy_note(OLD_NOTE_B, OLD_EVENT_B, "right note", 4.0),
            "right fork",
        );
        repository.push(&mut left).unwrap();
        repository.push(&mut right).unwrap();

        let mut joined = repository.pull(branch).unwrap();
        joined.commit(legacy_cancellation(OLD_EVENT_A), "causal rejoin");
        repository.push(&mut joined).unwrap();

        // An exact repeated assertion is an authored occurrence, not a new
        // semantic fact. It exercises overlap without weakening preservation.
        let mut redundant = repository.pull(branch).unwrap();
        redundant.commit(
            entity! { ExclusiveId::force_ref(&OLD_EVENT_A) @ event::summary: "event-a" },
            "redundant overlap",
        );
        repository.push(&mut redundant).unwrap();
        repository.close().unwrap();

        initialize_signer(&source, Some(&source_key)).unwrap();
        initialize_signer(&destination, Some(&destination_key)).unwrap();
        Fixture {
            _directory: directory,
            source,
            destination,
            source_key,
            destination_key,
        }
    }

    fn materialize(path: &Path, key: &Path) -> (TribleSet, PileReader, Vec<CollectionCommit>) {
        let signer = load_signer(path, Some(key)).unwrap();
        let mut pile = open_pile_strict(path).unwrap();
        let commits = discover_target(&mut pile, DEFAULT_SCOPE_ID)
            .unwrap()
            .commits()
            .iter()
            .copied()
            .filter(|commit| commit.public_key().raw == signer.verifying_key().to_bytes())
            .collect();
        let mut collection =
            triblespace::core::collection::Collection::new(pile, DEFAULT_SCOPE_ID, signer);
        let facts = collection.materialize().unwrap();
        let reader = collection.storage_mut().reader().unwrap();
        let pile = collection.into_storage();
        pile.close().unwrap();
        (facts, reader, commits)
    }

    #[test]
    fn authored_fragments_metadata_exports_and_blobs_are_preserved_exactly() {
        let fixture = fixture("uid-b");
        let frozen = freeze_source(&fixture.source).unwrap();
        let branch = frozen.legacy_branch(LEGACY_BRANCH_NAME).unwrap().unwrap();
        let mut projected =
            project_legacy_authored_commits(&frozen, &branch, validate_legacy_payloads).unwrap();
        projected.sort_unstable_by_key(|commit| commit.source);

        // Exercise all Fragment channels directly. The historical repository
        // archives facts and blobs, while the projector API remains capable of
        // carrying richer fragments produced by other frozen-source adapters.
        let original = projected[0].content.clone();
        let mut enriched = Fragment::new([EXTRA_EXPORT], original.facts().clone());
        *enriched.metafacts_mut() +=
            entity! { ExclusiveId::force_ref(&EXTRA_META_ENTITY) @ metadata::tag: &METADATA_MARKER }
                .into_facts();
        enriched.blobs_mut().union(original.blobs().clone());
        let sentinel = enriched.put::<LongString, _>("unreferenced resident closure".to_owned());
        projected[0].content = enriched;

        let mut enriched_metadata = projected[0].metadata.clone();
        let metadata_sentinel =
            enriched_metadata.put::<LongString, _>("metadata resident closure".to_owned());
        *enriched_metadata.metafacts_mut() += entity! {
            ExclusiveId::force_ref(&EXTRA_META_ENTITY) @ metadata::description: metadata_sentinel
        }
        .into_facts();
        projected[0].metadata = enriched_metadata;

        let expected = projected.clone();
        let plan = plan_projected(&branch, projected, frozen.reader()).unwrap();
        plan.verify_conservation().unwrap();
        assert_eq!(plan.commits().len(), expected.len());
        for (planned, projected) in plan.commits().iter().zip(&expected) {
            assert_eq!(planned.source, projected.source);
            assert_eq!(planned.legacy_content(), &projected.content);
            assert_eq!(planned.legacy_metadata(), &projected.metadata);
        }
        assert_eq!(
            plan.commits()[0]
                .legacy_content()
                .exports()
                .collect::<Vec<_>>(),
            vec![EXTRA_EXPORT]
        );
        let final_blobs = plan.commits()[0]
            .fragment()
            .blobs()
            .clone()
            .reader()
            .unwrap();
        assert!(final_blobs.metadata(sentinel).unwrap().is_some());
        assert!(final_blobs.metadata(metadata_sentinel).unwrap().is_some());

        publish(
            &frozen,
            &plan,
            &fixture.destination,
            Some(&fixture.destination_key),
        )
        .unwrap();
        let mut target = open_pile_strict(&fixture.destination).unwrap();
        let reader = target.reader().unwrap();
        assert!(reader.metadata(sentinel).unwrap().is_some());
        assert!(reader.metadata(metadata_sentinel).unwrap().is_some());
        target.close().unwrap();
    }

    #[test]
    fn plan_is_additive_deterministic_and_preserves_overlap_occurrences() {
        let fixture = fixture("uid-b");
        let frozen = freeze_source(&fixture.source).unwrap();
        let forward = plan(&frozen).unwrap();
        let again = plan(&frozen).unwrap();
        assert_eq!(forward, again);
        forward.verify_conservation().unwrap();

        assert!(forward
            .added_facts()
            .intersect(forward.original_facts())
            .is_empty());
        let mut expected = forward.original_facts().clone();
        expected += forward.added_facts().clone();
        assert_eq!(forward.materialized_facts(), expected);
        assert_eq!(forward.report().authored_commits, 6);
        assert_eq!(forward.report().authored_empty_commits, 1);
        assert_eq!(forward.report().contentless_merges, 1);
        assert_eq!(forward.report().legacy_events, 2);
        assert_eq!(forward.report().canonical_events, 2);
        assert_eq!(forward.report().legacy_notes, 2);
        assert_eq!(forward.report().canonical_notes, 2);
        assert_eq!(forward.report().legacy_cancellation_occurrences, 1);
        assert_eq!(forward.report().canonical_cancellations, 1);
        assert_eq!(forward.report().redundant_occurrences, 1);
        assert_eq!(
            forward.report().legacy_fact_occurrences,
            forward.report().preserved_facts + 1,
            "the duplicate summary remains in both authored commits"
        );

        let branch = frozen.legacy_branch(LEGACY_BRANCH_NAME).unwrap().unwrap();
        let mut projected =
            project_legacy_authored_commits(&frozen, &branch, validate_legacy_payloads).unwrap();
        projected.reverse();
        let mut reversed_branch = branch.clone();
        reversed_branch.deltas.reverse();
        let reversed = plan_projected(&reversed_branch, projected, frozen.reader()).unwrap();
        assert_eq!(forward, reversed);
    }

    #[test]
    fn detached_target_and_in_place_publication_are_exact_and_idempotent() {
        let fixture = fixture("uid-b");
        let source_before = fs::read(&fixture.source).unwrap();
        let frozen = freeze_source(&fixture.source).unwrap();
        let plan = plan(&frozen).unwrap();
        assert_eq!(fs::read(&fixture.source).unwrap(), source_before);

        let first = publish(
            &frozen,
            &plan,
            &fixture.destination,
            Some(&fixture.destination_key),
        )
        .unwrap();
        let target_length = fs::metadata(&fixture.destination).unwrap().len();
        let second = publish(
            &frozen,
            &plan,
            &fixture.destination,
            Some(&fixture.destination_key),
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(
            fs::metadata(&fixture.destination).unwrap().len(),
            target_length
        );

        let (target_facts, target_reader, target_commits) =
            materialize(&fixture.destination, &fixture.destination_key);
        assert_eq!(target_facts, plan.materialized_facts());
        let catalog = planner::validate_catalog(&target_reader, &target_facts).unwrap();
        assert_eq!(catalog.events.len(), 2);
        assert_eq!(catalog.notes.len(), 2);
        assert_eq!(catalog.cancellations.len(), 1);
        assert!(catalog.is_cancelled(plan.event_ids()[&OLD_EVENT_A]));
        assert!(catalog.is_cancelled(plan.event_ids()[&OLD_EVENT_B]));
        assert!(target_facts.iter().any(|fact| fact.e() == &OLD_EVENT_A));
        assert!(target_facts.iter().any(|fact| fact.e() == &OLD_NOTE_A));

        let mut messages = BTreeSet::new();
        let mut marker_count = 0;
        let mut created_count = 0;
        for commit in &target_commits {
            let metadata: TribleSet = target_reader.get(commit.metadata()).unwrap();
            for (message,) in find!(
                (message: crate::planner::TextHandle),
                pattern!(&metadata, [{ _?subject @ metadata::description: ?message }])
            ) {
                let message: View<str> = target_reader.get(message).unwrap();
                messages.insert(message.to_string());
            }
            marker_count += find!(
                (value: Id),
                pattern!(&metadata, [{ _?subject @ metadata::tag: ?value }])
            )
            .filter(|(value,)| value == &METADATA_MARKER)
            .count();
            created_count += metadata
                .iter()
                .filter(|fact| fact.a() == &metadata::created_at.id())
                .count();
        }
        assert_eq!(target_commits.len(), plan.report().authored_commits);
        assert_eq!(created_count, plan.report().authored_commits);
        assert_eq!(marker_count, 1);
        assert!(messages.contains("root"));
        assert!(messages.contains("authored empty"));
        assert!(messages.contains("left fork"));
        assert!(messages.contains("right fork"));
        assert!(messages.contains("causal rejoin"));
        assert!(messages.contains("redundant overlap"));
        assert!(messages.contains("semantic provenance"));
        let expected_collection =
            triblespace::core::collection::simplearchive_union::descriptor(DEFAULT_SCOPE_ID)
                .handle();
        assert!(target_commits
            .iter()
            .all(|commit| commit.collection() == expected_collection));
        assert_eq!(fs::read(&fixture.source).unwrap(), source_before);

        let in_place_first =
            publish(&frozen, &plan, &fixture.source, Some(&fixture.source_key)).unwrap();
        let in_place_length = fs::metadata(&fixture.source).unwrap().len();
        let in_place_second =
            publish(&frozen, &plan, &fixture.source, Some(&fixture.source_key)).unwrap();
        assert_eq!(in_place_first, in_place_second);
        assert_eq!(
            fs::metadata(&fixture.source).unwrap().len(),
            in_place_length
        );

        let (in_place_facts, in_place_reader, _) =
            materialize(&fixture.source, &fixture.source_key);
        assert_eq!(in_place_facts, plan.materialized_facts());
        planner::validate_catalog(&in_place_reader, &in_place_facts).unwrap();
        let mut pile = open_pile_strict(&fixture.source).unwrap();
        assert!(pile.pins().unwrap().next().is_some());
        pile.close().unwrap();
    }

    fn concurrent_genesis_source() -> (TestDirectory, std::path::PathBuf) {
        let directory = TestDirectory::new();
        let path = directory.0.join("fork-conflict.pile");
        File::create(&path).unwrap();
        let storage = open_pile_strict(&path).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0x62; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository.create_branch(LEGACY_BRANCH_NAME, None).unwrap();
        let mut root = repository.pull(branch).unwrap();
        root.commit(vocabulary(), "vocabulary");
        repository.push(&mut root).unwrap();

        let mut left = repository.pull(branch).unwrap();
        let mut right = repository.pull(branch).unwrap();
        left.commit(
            legacy_event(OLD_EVENT_A, "forked", STATUS_CONFIRMED, 1.0),
            "left genesis",
        );
        right.commit(
            legacy_event(OLD_EVENT_A, "forked", STATUS_CONFIRMED, 1.0),
            "right genesis",
        );
        repository.push(&mut left).unwrap();
        repository.push(&mut right).unwrap();
        repository.close().unwrap();
        (directory, path)
    }

    #[test]
    fn duplicate_uids_and_concurrent_genesis_forks_fail_before_publication() {
        let duplicate = fixture("uid-a");
        let frozen = freeze_source(&duplicate.source).unwrap();
        let error = plan(&frozen).unwrap_err();
        assert!(format!("{error:#}").contains("share UID"));

        let (_directory, path) = concurrent_genesis_source();
        let frozen = freeze_source(&path).unwrap();
        let error = plan(&frozen).unwrap_err();
        assert!(format!("{error:#}").contains("concurrent genesis assertions"));
    }

    #[test]
    fn semantically_identical_legacy_notes_share_one_intrinsic_shadow() {
        let directory = TestDirectory::new();
        let path = directory.0.join("note-overlap.pile");
        File::create(&path).unwrap();
        let storage = open_pile_strict(&path).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0x63; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository.create_branch(LEGACY_BRANCH_NAME, None).unwrap();
        let mut workspace = repository.pull(branch).unwrap();
        workspace.commit(
            vocabulary() + legacy_event(OLD_EVENT_A, "one", STATUS_CONFIRMED, 1.0),
            "event",
        );
        repository.push(&mut workspace).unwrap();
        workspace.commit(
            legacy_note(OLD_NOTE_A, OLD_EVENT_A, "same", 2.0),
            "first note",
        );
        repository.push(&mut workspace).unwrap();
        workspace.commit(
            legacy_note(OLD_NOTE_B, OLD_EVENT_A, "same", 2.0),
            "second note",
        );
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();

        let frozen = freeze_source(&path).unwrap();
        let plan = plan(&frozen).unwrap();
        assert_eq!(plan.report().legacy_notes, 2);
        assert_eq!(plan.report().canonical_notes, 1);
        assert_eq!(plan.note_ids()[&OLD_NOTE_A], plan.note_ids()[&OLD_NOTE_B]);
        let added_occurrences: usize = plan
            .commits()
            .iter()
            .map(|commit| commit.additions().facts().len())
            .sum();
        assert_eq!(added_occurrences, plan.added_facts().len());
    }

    #[test]
    fn shadows_overlapping_already_intrinsic_legacy_records_add_only_missing_facts() {
        let directory = TestDirectory::new();
        let path = directory.0.join("intrinsic-overlap.pile");
        File::create(&path).unwrap();

        let probe = EventDraft {
            uid: "already-intrinsic".to_owned(),
            summary: "probe".to_owned(),
            description: None,
            time: span(1.0, 2.0),
            rrule: None,
            rdates: BTreeSet::new(),
            exdates: BTreeSet::new(),
            location: None,
            status: STATUS_CONFIRMED.to_owned(),
            transp: TRANSP_OPAQUE.to_owned(),
            attendees: BTreeSet::new(),
            organizer: None,
            sequence: None,
        };
        let event_id = planner::event_fragment(&probe).unwrap().root().unwrap();
        let note_id = planner::note_fragment(event_id, "same", at(2.0))
            .unwrap()
            .root()
            .unwrap();

        let storage = open_pile_strict(&path).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0x64; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository.create_branch(LEGACY_BRANCH_NAME, None).unwrap();
        let mut workspace = repository.pull(branch).unwrap();
        workspace.commit(
            vocabulary()
                + legacy_event(event_id, "already-intrinsic", STATUS_CONFIRMED, 1.0)
                + legacy_note(note_id, event_id, "same", 2.0),
            "already intrinsic",
        );
        repository.push(&mut workspace).unwrap();
        workspace.commit(legacy_cancellation(event_id), "legacy cancellation");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();

        let frozen = freeze_source(&path).unwrap();
        let plan = plan(&frozen).unwrap();
        assert_eq!(plan.event_ids()[&event_id], event_id);
        assert_eq!(plan.note_ids()[&note_id], note_id);
        assert!(plan.report().overlapping_shadow_facts > 0);
        assert_eq!(plan.report().canonical_cancellations, 1);
        assert_eq!(plan.added_facts().len(), 2);
        assert!(plan
            .added_facts()
            .intersect(plan.original_facts())
            .is_empty());
        let catalog =
            planner::validate_catalog(frozen.reader(), &plan.materialized_facts()).unwrap();
        assert_eq!(catalog.events.len(), 1);
        assert_eq!(catalog.notes.len(), 1);
        assert!(catalog.is_cancelled(event_id));

        let canonical = planner::event_fragment(&EventDraft {
            uid: "already-intrinsic".to_owned(),
            summary: "event-b".to_owned(),
            description: Some(format!("description-{event_id:x}")),
            time: span(11.0, 21.0),
            rrule: None,
            rdates: BTreeSet::new(),
            exdates: BTreeSet::new(),
            location: None,
            status: STATUS_CONFIRMED.to_owned(),
            transp: TRANSP_OPAQUE.to_owned(),
            attendees: BTreeSet::new(),
            organizer: None,
            sequence: None,
        })
        .unwrap();
        assert_eq!(
            planner::event_facts(&plan.materialized_facts(), event_id),
            canonical.facts().clone()
        );
    }
}
