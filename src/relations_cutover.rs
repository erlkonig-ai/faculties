//! Stopped-world additive projection of every published legacy Relations shape.
//!
//! The old branch accumulated mutable person/group attributes, timestamped
//! retirement events, anchor-direct groups, random-id full group snapshots,
//! the later intrinsic group-snapshot schema, and direct identity edges.
//! This transform validates that complete ontology and replays the verified
//! repository DAG into the collection-native snapshot algebra. Every authored
//! legacy fragment remains byte-for-byte present in its corresponding native
//! commit; canonical intrinsic snapshots are additive shadows. Source time is
//! never used to choose a winner: source forks remain target forks, and scalar
//! ambiguity trapped inside a squashed authored delta is represented by
//! concurrent intrinsic profile heads.
//!
//! `label_norm`/`alias_norm` are derived lookup exhaust and are intentionally
//! recomputed by current readers. Stable person anchors retain additive source
//! and creation observations; stable group anchors retain additive creation
//! observations. Exact repository and semantic commit metadata, including its
//! attachments, remains on the corresponding authored collection commit.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::attribute::Attribute;
use triblespace::core::blob::encodings::longstring::LongString;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::id::{ExclusiveId, Id};
use triblespace::core::inline::encodings::shortstring::ShortString;
use triblespace::core::inline::Inline;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::BlobStoreGet;
use triblespace::core::trible::{Fragment, TribleSet};
use triblespace::macros::{attributes, entity, id_hex};
use triblespace::prelude::{blobencodings, inlineencodings};

use crate::collection_cutover::{
    project_legacy_authored_commits, publish_fragments, FrozenLegacyBranch, FrozenLegacyDelta,
    FrozenSource, LegacyCommitCoordinate, LegacyPinCoordinate, ProjectedLegacyCommit,
};
use crate::relations::{self as current, ProfileInput};
use crate::schemas::relations as schema;
use crate::schemas::relations::{group, KIND_GROUP, KIND_PERSON_ID};

use crate::schemas::relations::LEGACY_BRANCH_NAME;
const KIND_RETIRE_ID: Id = id_hex!("CB9251505F663A9232C632CC9E68863A");
const KIND_UNRETIRE_ID: Id = id_hex!("D2D4AFCAD74CBD193B2EB7FE94AE27E9");

mod legacy {
    use super::*;

    attributes! {
        "8F162B593D390E1424394DBF6883A72C" unsafe as alias: inlineencodings::ShortString;
        "299E28A10114DC8C3B1661CD90CB8DF6" unsafe as label_norm: inlineencodings::ShortString;
        "3E8812F6D22B2C93E2BCF0CE3C8C1979" unsafe as alias_norm: inlineencodings::ShortString;
        "32B22FBA3EC2ADC3FFEB48483FE8961F" unsafe as affinity: inlineencodings::ShortString;
        "F0AD0BBFAC4C4C899637573DC965622E" unsafe as first_name: inlineencodings::Handle<blobencodings::LongString>;
        "764DD765142B3F4725B614BD3B9118EC" unsafe as last_name: inlineencodings::Handle<blobencodings::LongString>;
        "DC0916CB5F640984EFE359A33105CA9A" unsafe as display_name: inlineencodings::Handle<blobencodings::LongString>;
        "9B3329149D54CB9A8E8075E4AA862649" unsafe as teams_user_id: inlineencodings::ShortString;
        "B563A063474CBE62ED25A8D0E9A1853C" unsafe as email: inlineencodings::ShortString;
        "9C2B10C740FCF7064A46F9B43D1FE278" unsafe as phone: inlineencodings::ShortString;
        "E3D486BD7C9C088D908DF1B9E1F4D925" unsafe as company: inlineencodings::Handle<blobencodings::LongString>;
        "173B771D35FEE90B83F2731DD3C59EF8" unsafe as position: inlineencodings::Handle<blobencodings::LongString>;
        "5A71C103E026FC1AC01E35EDAC274A5C" unsafe as profile_url: inlineencodings::Handle<blobencodings::LongString>;
        "686FD344CD64C3F9C981C4028B1B6B9E" unsafe as source: inlineencodings::ShortString;
        "0FCF3A17B2EBE7243BDDD791B901E2D6" unsafe as same_as: inlineencodings::GenId;
        "A89DC2F250432322D429D0E51316B6F3" unsafe as distinct_from: inlineencodings::GenId;
        "EB09A042DE6AA778D05C1EF795C434EE" unsafe as review_candidate: inlineencodings::GenId;
        "C9D3F48C660DADBDBFA32F30F595415A" unsafe as subject: inlineencodings::GenId;

        // The first Relations generation used these Atlas meanings directly.
        // shortname was the label; the then-current name attribute was display
        // text.  Both remain in the live squashed history.
        "2E26F8BA886495A8DF04ACF0ED3ACBD4" unsafe as historical_shortname: inlineencodings::ShortString;
        "25031BF40F16F7F492213DEC04B644B9" unsafe as historical_display_name: inlineencodings::Handle<blobencodings::LongString>;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RelationsCommitPartition {
    pub source: LegacyCommitCoordinate,
    pub content: Fragment,
    pub metadata: Fragment,
    pub preserved: Fragment,
}

/// One native commit planned from one legacy authored commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationsMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
    preserved: Fragment,
}

impl RelationsMigrationCommit {
    /// Exact authored content, metadata, and resident blobs that must remain
    /// present in [`Self::fragment`].
    pub fn preserved_fragment(&self) -> &Fragment {
        &self.preserved
    }
}

/// Conservation summary for the stopped-world replay.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RelationsMigrationReport {
    pub authored_commits: usize,
    pub original_facts: usize,
    pub preserved_original_facts: usize,
    pub added_canonical_facts: usize,
    pub materialized_facts: usize,
    pub people: usize,
    pub groups: usize,
}

/// Pure Relations migration plan ready for native collection publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationsMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<RelationsMigrationCommit>,
    original: TribleSet,
    additions: TribleSet,
    report: RelationsMigrationReport,
}

impl RelationsMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[RelationsMigrationCommit] {
        &self.commits
    }

    pub const fn report(&self) -> &RelationsMigrationReport {
        &self.report
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    pub fn added_facts(&self) -> &TribleSet {
        &self.additions
    }

    pub fn materialized_facts(&self) -> TribleSet {
        let mut facts = TribleSet::new();
        for commit in &self.commits {
            facts += commit.fragment.facts().clone();
        }
        facts
    }

    /// Recheck the migration law across content facts and every authored
    /// fragment channel: output = exact legacy facts UNION canonical shadows.
    pub fn verify_conservation(&self) -> Result<()> {
        if self
            .additions
            .iter()
            .any(|fact| self.original.contains(fact))
        {
            bail!("Relations migration classifies a legacy fact as a canonical addition");
        }
        let mut expected = self.original.clone();
        expected += self.additions.clone();
        if self.materialized_facts() != expected {
            bail!(
                "planned Relations collection is not exactly legacy facts union canonical shadows"
            );
        }
        for commit in &self.commits {
            let mut retained = commit.fragment.clone();
            retained += commit.preserved.clone();
            if retained != commit.fragment {
                bail!(
                    "Relations commit projected from {} dropped authored content, metadata, or resident blobs",
                    hex::encode_upper(commit.source.commit.raw)
                );
            }
        }
        if self.report.original_facts != self.original.len()
            || self.report.preserved_original_facts != self.original.len()
            || self.report.added_canonical_facts != self.additions.len()
            || self.report.materialized_facts != expected.len()
        {
            bail!("Relations migration conservation report disagrees with the planned facts");
        }
        Ok(())
    }

    fn validate(&self, reader: &PileReader) -> Result<()> {
        self.verify_conservation()?;
        let mut complete = Fragment::empty();
        for commit in &self.commits {
            complete += commit.fragment.clone();
        }
        let validated = current::validate_catalog_union(reader, &TribleSet::new(), &complete)
            .context("validate planned Relations collection and attachments")?;
        if validated != self.materialized_facts() {
            bail!("planned Relations fragment union changed during validation");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PartitionedRelationsRewrite {
    commits: Vec<RelationsCommitPartition>,
    original: TribleSet,
    additions: TribleSet,
}

/// Plan the complete legacy Relations branch without mutating either pile.
pub fn plan(source: &FrozenSource) -> Result<RelationsMigrationPlan> {
    let branch = source
        .legacy_branch(LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Relations branch"))?;
    let projected = project_legacy_authored_commits(source, &branch, validate_legacy_payloads)
        .context("project frozen Relations authored commits")?;
    let rewritten = rewrite_relations_commits(&branch, &projected, source.reader())
        .context("add intrinsic Relations shadows to the preserved authored DAG")?;
    let mut commits = Vec::with_capacity(rewritten.commits.len());
    for mut partition in rewritten.commits {
        partition.content.describe_with(partition.metadata);
        commits.push(RelationsMigrationCommit {
            source: partition.source,
            fragment: partition.content,
            preserved: partition.preserved,
        });
    }
    let materialized = commits.iter().fold(TribleSet::new(), |mut facts, commit| {
        facts += commit.fragment.facts().clone();
        facts
    });
    let report = RelationsMigrationReport {
        authored_commits: commits.len(),
        original_facts: rewritten.original.len(),
        preserved_original_facts: rewritten
            .original
            .iter()
            .filter(|fact| materialized.contains(fact))
            .count(),
        added_canonical_facts: rewritten.additions.len(),
        materialized_facts: materialized.len(),
        people: current::person_anchors(&materialized).len(),
        groups: current::group_anchors(&materialized).len(),
    };
    let plan = RelationsMigrationPlan {
        source_pin: branch.pin_coordinate(),
        commits,
        original: rewritten.original,
        additions: rewritten.additions,
        report,
    };
    plan.validate(source.reader())?;
    Ok(plan)
}

/// Publish a frozen plan through the native collection facade.
pub fn publish(
    source: &FrozenSource,
    plan: &RelationsMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Relations migration plan does not belong to this frozen source");
    }
    plan.validate(source.reader())?;
    publish_fragments(
        target,
        key,
        schema::DEFAULT_SCOPE_ID,
        plan.commits.iter().map(|commit| commit.fragment.clone()),
    )
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
struct ProfileData {
    label: String,
    aliases: BTreeSet<String>,
    affinities: BTreeSet<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    display_name: Option<String>,
    note: Option<String>,
    teams_user_ids: BTreeSet<String>,
    emails: BTreeSet<String>,
    phones: BTreeSet<String>,
    company: Option<String>,
    position: Option<String>,
    profile_urls: BTreeSet<String>,
}

impl ProfileData {
    fn input(&self) -> ProfileInput {
        ProfileInput {
            label: self.label.clone(),
            aliases: self.aliases.iter().cloned().collect(),
            affinities: self.affinities.iter().cloned().collect(),
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            display_name: self.display_name.clone(),
            note: self.note.clone(),
            teams_user_ids: self.teams_user_ids.iter().cloned().collect(),
            emails: self.emails.iter().cloned().collect(),
            phones: self.phones.iter().cloned().collect(),
            company: self.company.clone(),
            position: self.position.clone(),
            profile_urls: self.profile_urls.iter().cloned().collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ProfileHead {
    id: Id,
    data: ProfileData,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct LifecycleHead {
    id: Id,
    retired: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct GroupData {
    name: String,
    members: BTreeSet<Id>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct GroupHead {
    id: Id,
    data: GroupData,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct VerdictHead {
    id: Id,
    same: bool,
}

#[derive(Clone, Debug, Default)]
struct ReplayState {
    profiles: BTreeMap<Id, Vec<ProfileHead>>,
    lifecycles: BTreeMap<Id, Vec<LifecycleHead>>,
    groups: BTreeMap<Id, Vec<GroupHead>>,
    verdicts: BTreeMap<(Id, Id), Vec<VerdictHead>>,
    old_group_ids: BTreeMap<Id, Id>,
}

fn dedup<T: Ord>(values: &mut Vec<T>) {
    values.sort();
    values.dedup();
}

fn merge_map<K: Ord + Copy, V: Ord + Clone>(
    into: &mut BTreeMap<K, Vec<V>>,
    from: &BTreeMap<K, Vec<V>>,
) {
    for (&key, values) in from {
        into.entry(key).or_default().extend(values.iter().cloned());
    }
    for values in into.values_mut() {
        dedup(values);
    }
}

fn merge_parent_states(
    delta: &FrozenLegacyDelta,
    states: &BTreeMap<[u8; 32], ReplayState>,
) -> Result<ReplayState> {
    let mut merged = ReplayState::default();
    for parent in &delta.parents {
        let state = states.get(&parent.raw).ok_or_else(|| {
            anyhow!(
                "legacy Relations commit {} has unavailable parent {}",
                hex::encode_upper(delta.commit.raw),
                hex::encode_upper(parent.raw)
            )
        })?;
        merge_map(&mut merged.profiles, &state.profiles);
        merge_map(&mut merged.lifecycles, &state.lifecycles);
        merge_map(&mut merged.groups, &state.groups);
        merge_map(&mut merged.verdicts, &state.verdicts);
        for (&old, &new) in &state.old_group_ids {
            if let Some(other) = merged.old_group_ids.insert(old, new) {
                if other != new {
                    bail!("legacy group snapshot {old:X} has a non-deterministic remap");
                }
            }
        }
    }
    Ok(merged)
}

fn inline_values<V: triblespace::core::inline::InlineEncoding>(
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

fn ids(
    facts: &TribleSet,
    entity: Id,
    attribute: &Attribute<inlineencodings::GenId>,
) -> Result<BTreeSet<Id>> {
    inline_values(facts, entity, attribute)
        .into_iter()
        .map(|value| {
            value
                .try_from_inline()
                .map_err(|error| anyhow!("decode legacy Relations id: {error:?}"))
        })
        .collect()
}

fn shorts(
    facts: &TribleSet,
    entity: Id,
    attribute: &Attribute<ShortString>,
) -> Result<BTreeSet<String>> {
    inline_values(facts, entity, attribute)
        .into_iter()
        .map(|value| {
            value
                .try_from_inline()
                .map_err(|error| anyhow!("decode legacy Relations text: {error:?}"))
        })
        .collect()
}

fn longs(
    reader: &PileReader,
    facts: &TribleSet,
    entity: Id,
    attribute: &Attribute<inlineencodings::Handle<LongString>>,
) -> Result<BTreeSet<String>> {
    inline_values(facts, entity, attribute)
        .into_iter()
        .map(|handle| {
            let text: View<str> = reader.get(handle).with_context(|| {
                format!(
                    "read legacy Relations text {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
            Ok(text.to_string())
        })
        .collect()
}

fn tags(facts: &TribleSet, entity: Id) -> Result<BTreeSet<Id>> {
    ids(facts, entity, &metadata::tag)
}

fn entities_with(facts: &TribleSet, attribute: Id) -> BTreeSet<Id> {
    facts
        .iter()
        .filter(|fact| fact.a() == &attribute)
        .map(|fact| *fact.e())
        .collect()
}

fn validate_point(entity: Id, values: Vec<Inline<inlineencodings::NsTAIInterval>>) -> Result<()> {
    if values.len() != 1 {
        bail!(
            "legacy Relations entity {entity:X} has {} timestamps; expected one",
            values.len()
        );
    }
    let (start, end): (i128, i128) = values[0]
        .try_from_inline()
        .map_err(|error| anyhow!("decode legacy Relations timestamp: {error:?}"))?;
    if start != end {
        bail!("legacy Relations entity {entity:X} timestamp is not a point");
    }
    Ok(())
}

fn validate_legacy_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for attribute in [
        &metadata::name,
        &metadata::description,
        &legacy::first_name,
        &legacy::last_name,
        &legacy::display_name,
        &legacy::company,
        &legacy::position,
        &legacy::profile_url,
        &legacy::historical_display_name,
    ] {
        for fact in facts.iter().filter(|fact| fact.a() == &attribute.id()) {
            let handle = *fact.v::<inlineencodings::Handle<LongString>>();
            let _: View<str> = reader.get(handle).with_context(|| {
                format!(
                    "read legacy Relations payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

fn known_attributes() -> BTreeSet<Id> {
    [
        metadata::tag.id(),
        metadata::name.id(),
        metadata::description.id(),
        metadata::created_at.id(),
        metadata::supersedes.id(),
        group::member.id(),
        group::snapshot_of.id(),
        legacy::alias.id(),
        legacy::label_norm.id(),
        legacy::alias_norm.id(),
        legacy::affinity.id(),
        legacy::first_name.id(),
        legacy::last_name.id(),
        legacy::display_name.id(),
        legacy::teams_user_id.id(),
        legacy::email.id(),
        legacy::phone.id(),
        legacy::company.id(),
        legacy::position.id(),
        legacy::profile_url.id(),
        legacy::source.id(),
        legacy::same_as.id(),
        legacy::distinct_from.id(),
        legacy::review_candidate.id(),
        legacy::subject.id(),
        legacy::historical_shortname.id(),
        legacy::historical_display_name.id(),
    ]
    .into_iter()
    .collect()
}

fn person_attributes() -> BTreeSet<Id> {
    [
        metadata::tag.id(),
        metadata::name.id(),
        metadata::description.id(),
        metadata::created_at.id(),
        legacy::alias.id(),
        legacy::label_norm.id(),
        legacy::alias_norm.id(),
        legacy::affinity.id(),
        legacy::first_name.id(),
        legacy::last_name.id(),
        legacy::display_name.id(),
        legacy::teams_user_id.id(),
        legacy::email.id(),
        legacy::phone.id(),
        legacy::company.id(),
        legacy::position.id(),
        legacy::profile_url.id(),
        legacy::source.id(),
        legacy::same_as.id(),
        legacy::distinct_from.id(),
        legacy::review_candidate.id(),
        legacy::historical_shortname.id(),
        legacy::historical_display_name.id(),
    ]
    .into_iter()
    .collect()
}

fn validate_legacy_catalog(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    validate_legacy_payloads(reader, facts)?;
    for attribute in [
        &legacy::alias,
        &legacy::label_norm,
        &legacy::alias_norm,
        &legacy::affinity,
        &legacy::teams_user_id,
        &legacy::email,
        &legacy::phone,
        &legacy::source,
        &legacy::historical_shortname,
    ] {
        for fact in facts.iter().filter(|fact| fact.a() == &attribute.id()) {
            let _: String = (*fact.v::<ShortString>())
                .try_from_inline()
                .map_err(|error| {
                    anyhow!(
                        "decode legacy Relations short text on {:X}: {error:?}",
                        fact.e()
                    )
                })?;
        }
    }
    let known = known_attributes();
    if let Some(fact) = facts.iter().find(|fact| !known.contains(fact.a())) {
        bail!(
            "legacy Relations contains unknown attribute {:X} on {:X}",
            fact.a(),
            fact.e()
        );
    }

    let tagged = entities_with(facts, metadata::tag.id());
    let mut people = BTreeSet::new();
    let mut groups = BTreeSet::new();
    let mut events = BTreeSet::new();
    for entity in tagged {
        let kinds = tags(facts, entity)?;
        if kinds.len() != 1 {
            bail!(
                "legacy Relations entity {entity:X} has {} kinds",
                kinds.len()
            );
        }
        match *kinds.iter().next().expect("one kind") {
            KIND_PERSON_ID => {
                people.insert(entity);
            }
            KIND_GROUP => {
                groups.insert(entity);
            }
            KIND_RETIRE_ID | KIND_UNRETIRE_ID => {
                events.insert(entity);
            }
            kind => bail!("legacy Relations entity {entity:X} has unknown kind {kind:X}"),
        }
    }

    let person_allowed = person_attributes();
    for &person in &people {
        if let Some(fact) = facts
            .iter()
            .find(|fact| fact.e() == &person && !person_allowed.contains(fact.a()))
        {
            bail!(
                "legacy person {person:X} carries invalid attribute {:X}",
                fact.a()
            );
        }
    }
    for &group_id in &groups {
        let allowed = BTreeSet::from([
            metadata::tag.id(),
            metadata::name.id(),
            metadata::created_at.id(),
            legacy::label_norm.id(),
            group::member.id(),
        ]);
        if let Some(fact) = facts
            .iter()
            .find(|fact| fact.e() == &group_id && !allowed.contains(fact.a()))
        {
            bail!(
                "legacy group {group_id:X} carries invalid attribute {:X}",
                fact.a()
            );
        }
    }
    for &event in &events {
        let entity_facts: Vec<_> = facts.iter().filter(|fact| fact.e() == &event).collect();
        let allowed = BTreeSet::from([
            metadata::tag.id(),
            legacy::subject.id(),
            metadata::created_at.id(),
        ]);
        if entity_facts.len() != 3 || entity_facts.iter().any(|fact| !allowed.contains(fact.a())) {
            bail!("legacy lifecycle event {event:X} is not an exact three-field event");
        }
        if ids(facts, event, &legacy::subject)?.len() != 1 {
            bail!("legacy lifecycle event {event:X} does not have one subject");
        }
        validate_point(event, inline_values(facts, event, &metadata::created_at))?;
    }
    for entity in entities_with(facts, metadata::created_at.id()) {
        validate_point(entity, inline_values(facts, entity, &metadata::created_at))?;
    }

    // The first full-state group writer (e017f6b) deliberately used `ufoid`
    // snapshot subjects.  b08af6b later sealed this same exact record shape
    // intrinsically.  Both generations are valid source history; the cutover
    // validates the exact fields/DAG here and deterministically remaps either
    // subject form to the current intrinsic record below.
    let snapshots = entities_with(facts, group::snapshot_of.id());
    for snapshot in &snapshots {
        let allowed = BTreeSet::from([
            group::snapshot_of.id(),
            metadata::name.id(),
            group::member.id(),
            metadata::supersedes.id(),
            legacy::label_norm.id(),
            metadata::created_at.id(),
        ]);
        let entity_facts: Vec<_> = facts.iter().filter(|fact| fact.e() == snapshot).collect();
        if let Some(fact) = entity_facts.iter().find(|fact| !allowed.contains(fact.a())) {
            bail!(
                "legacy group snapshot {snapshot:X} carries invalid attribute {:X}",
                fact.a()
            );
        }
        let anchors = ids(facts, *snapshot, &group::snapshot_of)?;
        let names = inline_values(facts, *snapshot, &metadata::name);
        if anchors.len() != 1 || names.len() != 1 {
            bail!("legacy group snapshot {snapshot:X} lacks one anchor/name");
        }
        let members: Vec<_> = ids(facts, *snapshot, &group::member)?.into_iter().collect();
        let predecessors: Vec<_> = ids(facts, *snapshot, &metadata::supersedes)?
            .into_iter()
            .collect();
        let anchor = *anchors.iter().next().expect("one anchor");
        if !groups.contains(&anchor) {
            bail!("legacy group snapshot {snapshot:X} names an undeclared group");
        }
        for member in members {
            if !people.contains(&member) {
                bail!("legacy group snapshot {snapshot:X} names undeclared member {member:X}");
            }
        }
        for predecessor in predecessors {
            let predecessor_anchors = ids(facts, predecessor, &group::snapshot_of)?;
            if predecessor_anchors != BTreeSet::from([anchor]) {
                bail!(
                    "legacy group snapshot {snapshot:X} supersedes missing or cross-group {predecessor:X}"
                );
            }
        }
    }

    let vocabulary = if entity_facts(facts, KIND_PERSON_ID).is_empty() {
        BTreeSet::new()
    } else {
        let exact = entity_facts(facts, KIND_PERSON_ID);
        if exact.len() != 2
            || inline_values(facts, KIND_PERSON_ID, &metadata::name).len() != 1
            || shorts(facts, KIND_PERSON_ID, &legacy::historical_shortname)?
                != BTreeSet::from(["person".to_owned()])
        {
            bail!("historical Relations person-kind vocabulary record is malformed");
        }
        BTreeSet::from([KIND_PERSON_ID])
    };
    let classified_before_exhaust: BTreeSet<Id> = people
        .iter()
        .chain(&groups)
        .chain(&events)
        .chain(&snapshots)
        .chain(&vocabulary)
        .copied()
        .collect();
    // One historical LinkedIn path could leave a provenance-only subject when
    // every semantic person assertion deduplicated away. It is neither an
    // anchor nor a profile. Accept only that exact one-field exhaust shape; no
    // target anchor is invented for it.
    let provenance_exhaust: BTreeSet<Id> = facts
        .iter()
        .map(|fact| *fact.e())
        .filter(|entity| !classified_before_exhaust.contains(entity))
        .filter(|entity| {
            let record = entity_facts(facts, *entity);
            record.len() == 1 && record.iter().all(|fact| fact.a() == &legacy::source.id())
        })
        .collect();
    let classified: BTreeSet<Id> = classified_before_exhaust
        .union(&provenance_exhaust)
        .copied()
        .collect();
    if let Some(entity) = facts
        .iter()
        .map(|fact| *fact.e())
        .find(|entity| !classified.contains(entity))
    {
        bail!("legacy Relations contains unclassified entity {entity:X}");
    }

    for &person in &people {
        for attribute in [
            &legacy::same_as,
            &legacy::distinct_from,
            &legacy::review_candidate,
        ] {
            for other in ids(facts, person, attribute)? {
                if person == other || !people.contains(&other) {
                    bail!("legacy identity edge {person:X} -> {other:X} has invalid endpoints");
                }
            }
        }
    }
    for &event in &events {
        let person = *ids(facts, event, &legacy::subject)?
            .iter()
            .next()
            .expect("one subject");
        if !people.contains(&person) {
            bail!("legacy lifecycle event {event:X} names undeclared person {person:X}");
        }
    }
    Ok(())
}

fn entity_facts(facts: &TribleSet, entity: Id) -> TribleSet {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity)
        .copied()
        .collect()
}

fn validate_immutable_source_shapes(
    branch: &FrozenLegacyBranch,
    complete: &TribleSet,
) -> Result<()> {
    let immutable: BTreeSet<Id> = entities_with(complete, group::snapshot_of.id())
        .union(
            &entities_with(complete, metadata::tag.id())
                .into_iter()
                .filter(|entity| {
                    tags(complete, *entity)
                        .map(|kinds| {
                            kinds.contains(&KIND_RETIRE_ID) || kinds.contains(&KIND_UNRETIRE_ID)
                        })
                        .unwrap_or(false)
                })
                .collect(),
        )
        .copied()
        .collect();
    let mut owners = BTreeMap::<Id, [u8; 32]>::new();
    for delta in &branch.deltas {
        for entity in delta
            .facts
            .iter()
            .map(|fact| *fact.e())
            .filter(|entity| immutable.contains(entity))
            .collect::<BTreeSet<_>>()
        {
            if entity_facts(&delta.facts, entity) != entity_facts(complete, entity) {
                bail!(
                    "immutable legacy Relations entity {entity:X} is split across authored deltas"
                );
            }
            if owners.insert(entity, delta.commit.raw).is_some() {
                bail!("immutable legacy Relations entity {entity:X} is repeated across deltas");
            }
        }
    }
    if owners.keys().copied().collect::<BTreeSet<_>>() != immutable {
        bail!("not every immutable legacy Relations entity has one authored source delta");
    }
    Ok(())
}

fn profile_patch_entities(facts: &TribleSet, people: &BTreeSet<Id>) -> BTreeSet<Id> {
    facts
        .iter()
        .filter(|fact| {
            people.contains(fact.e())
                && [
                    metadata::name.id(),
                    metadata::description.id(),
                    legacy::alias.id(),
                    legacy::affinity.id(),
                    legacy::first_name.id(),
                    legacy::last_name.id(),
                    legacy::display_name.id(),
                    legacy::teams_user_id.id(),
                    legacy::email.id(),
                    legacy::phone.id(),
                    legacy::company.id(),
                    legacy::position.id(),
                    legacy::profile_url.id(),
                    legacy::historical_shortname.id(),
                    legacy::historical_display_name.id(),
                ]
                .contains(fact.a())
        })
        .map(|fact| *fact.e())
        .collect()
}

fn expand_label(mut values: Vec<ProfileData>, choices: BTreeSet<String>) -> Vec<ProfileData> {
    if choices.is_empty() {
        return values;
    }
    let mut expanded = Vec::new();
    for value in values.drain(..) {
        for choice in &choices {
            let mut next = value.clone();
            next.label = choice.clone();
            expanded.push(next);
        }
    }
    dedup(&mut expanded);
    expanded
}

fn expand_optional(
    mut values: Vec<ProfileData>,
    choices: BTreeSet<String>,
    set: impl Fn(&mut ProfileData, Option<String>),
) -> Vec<ProfileData> {
    if choices.is_empty() {
        return values;
    }
    let mut expanded = Vec::new();
    for value in values.drain(..) {
        for choice in &choices {
            let mut next = value.clone();
            set(&mut next, Some(choice.clone()));
            expanded.push(next);
        }
    }
    dedup(&mut expanded);
    expanded
}

fn apply_profile_patch(
    reader: &PileReader,
    facts: &TribleSet,
    person: Id,
    bases: &[ProfileHead],
) -> Result<Vec<ProfileData>> {
    let mut states: Vec<ProfileData> = if bases.is_empty() {
        vec![ProfileData::default()]
    } else {
        bases.iter().map(|head| head.data.clone()).collect()
    };
    dedup(&mut states);

    let mut labels = longs(reader, facts, person, &metadata::name)?;
    labels.extend(shorts(facts, person, &legacy::historical_shortname)?);
    let aliases = shorts(facts, person, &legacy::alias)?;
    let affinities = shorts(facts, person, &legacy::affinity)?;
    let teams = shorts(facts, person, &legacy::teams_user_id)?;
    let emails = shorts(facts, person, &legacy::email)?;
    let phones = shorts(facts, person, &legacy::phone)?;

    states = expand_label(states, labels);
    states = expand_optional(
        states,
        longs(reader, facts, person, &legacy::first_name)?,
        |s, v| s.first_name = v,
    );
    states = expand_optional(
        states,
        longs(reader, facts, person, &legacy::last_name)?,
        |s, v| s.last_name = v,
    );
    let mut displays = longs(reader, facts, person, &legacy::display_name)?;
    displays.extend(longs(
        reader,
        facts,
        person,
        &legacy::historical_display_name,
    )?);
    states = expand_optional(states, displays, |s, v| s.display_name = v);
    states = expand_optional(
        states,
        longs(reader, facts, person, &metadata::description)?,
        |s, v| s.note = v,
    );
    states = expand_optional(
        states,
        longs(reader, facts, person, &legacy::company)?,
        |s, v| s.company = v,
    );
    states = expand_optional(
        states,
        longs(reader, facts, person, &legacy::position)?,
        |s, v| s.position = v,
    );

    for state in &mut states {
        state.aliases.extend(aliases.iter().cloned());
        state.affinities.extend(affinities.iter().cloned());
        state.teams_user_ids.extend(teams.iter().cloned());
        state.emails.extend(emails.iter().cloned());
        state.phones.extend(phones.iter().cloned());
        state
            .profile_urls
            .extend(longs(reader, facts, person, &legacy::profile_url)?);
    }
    let mut labelled = Vec::new();
    for state in states {
        if !state.label.is_empty() {
            labelled.push(state);
            continue;
        }
        let choices: BTreeSet<String> = if let Some(display) = &state.display_name {
            BTreeSet::from([display.clone()])
        } else if !state.emails.is_empty() {
            state.emails.clone()
        } else {
            state.aliases.clone()
        };
        if choices.is_empty() {
            bail!("legacy person {person:X} has no text usable as a required profile label");
        }
        for choice in choices {
            let mut variant = state.clone();
            variant.label = choice;
            labelled.push(variant);
        }
    }
    let mut states = labelled;
    dedup(&mut states);
    Ok(states)
}

fn emit(fragment: Fragment, partition: &mut Fragment, emitted: &mut TribleSet) {
    let fresh = fragment.facts().difference(emitted);
    *emitted += fresh.clone();
    let blobs = fragment.blobs().clone();
    *partition += Fragment::from_facts_and_blobs(fresh, blobs);
}

fn current_people(state: &ReplayState) -> BTreeSet<Id> {
    state.profiles.keys().copied().collect()
}

fn pair(a: Id, b: Id) -> (Id, Id) {
    if a < b {
        (a, b)
    } else {
        (b, a)
    }
}

fn handle_anchor_provenance(
    delta: &FrozenLegacyDelta,
    global_people: &BTreeSet<Id>,
    global_groups: &BTreeSet<Id>,
    output: &mut Fragment,
    emitted: &mut TribleSet,
) -> Result<()> {
    for &person in global_people {
        let sources: Vec<_> = shorts(&delta.facts, person, &legacy::source)?
            .into_iter()
            .collect();
        let observed = inline_values(&delta.facts, person, &metadata::created_at);
        if !sources.is_empty() || !observed.is_empty() {
            emit(
                current::person_provenance_fragment(person, sources, &observed)?,
                output,
                emitted,
            );
        }
    }
    for &group_id in global_groups {
        let observed = inline_values(&delta.facts, group_id, &metadata::created_at);
        if !observed.is_empty() {
            emit(
                current::group_provenance_fragment(group_id, &observed),
                output,
                emitted,
            );
        }
    }
    Ok(())
}

fn handle_person_profiles(
    reader: &PileReader,
    delta: &FrozenLegacyDelta,
    global_people: &BTreeSet<Id>,
    state: &mut ReplayState,
    output: &mut Fragment,
    emitted: &mut TribleSet,
) -> Result<BTreeSet<Id>> {
    let declared: BTreeSet<Id> = entities_with(&delta.facts, metadata::tag.id())
        .into_iter()
        .filter(|entity| {
            tags(&delta.facts, *entity)
                .map(|v| v.contains(&KIND_PERSON_ID))
                .unwrap_or(false)
        })
        .collect();
    let mut changed = profile_patch_entities(&delta.facts, global_people);
    changed.extend(declared.iter().copied());
    for person in changed {
        let bases = state.profiles.get(&person).cloned().unwrap_or_default();
        if bases.is_empty() && !declared.contains(&person) {
            bail!("legacy profile facts precede person declaration {person:X}");
        }
        let predecessor_ids: Vec<_> = bases.iter().map(|head| head.id).collect();
        let variants = apply_profile_patch(reader, &delta.facts, person, &bases)?;
        let mut heads = Vec::new();
        if bases.is_empty() {
            emit(
                entity! { ExclusiveId::force_ref(&person) @ metadata::tag: &KIND_PERSON_ID },
                output,
                emitted,
            );
        }
        for data in variants {
            let fragment = current::profile_fragment(person, data.input(), &predecessor_ids)?;
            let id = fragment.root().expect("profile root");
            emit(fragment, output, emitted);
            heads.push(ProfileHead { id, data });
        }
        dedup(&mut heads);
        state.profiles.insert(person, heads);
        if bases.is_empty() {
            let fragment = current::lifecycle_fragment(person, false, &[]);
            let id = fragment.root().expect("lifecycle root");
            emit(fragment, output, emitted);
            state
                .lifecycles
                .insert(person, vec![LifecycleHead { id, retired: false }]);
        }
    }
    Ok(declared)
}

fn handle_lifecycle_events(
    delta: &FrozenLegacyDelta,
    state: &mut ReplayState,
    output: &mut Fragment,
    emitted: &mut TribleSet,
) -> Result<()> {
    let mut updates = BTreeMap::<Id, BTreeSet<bool>>::new();
    for event in entities_with(&delta.facts, metadata::tag.id()) {
        let kinds = tags(&delta.facts, event)?;
        let retired = if kinds.contains(&KIND_RETIRE_ID) {
            Some(true)
        } else if kinds.contains(&KIND_UNRETIRE_ID) {
            Some(false)
        } else {
            None
        };
        let Some(retired) = retired else {
            continue;
        };
        let people = ids(&delta.facts, event, &legacy::subject)?;
        let person = *people
            .iter()
            .next()
            .ok_or_else(|| anyhow!("lifecycle event {event:X} has no subject"))?;
        updates.entry(person).or_default().insert(retired);
    }
    for (person, values) in updates {
        let bases =
            state.lifecycles.get(&person).cloned().ok_or_else(|| {
                anyhow!("lifecycle event names person {person:X} before declaration")
            })?;
        let predecessors: Vec<_> = bases.iter().map(|head| head.id).collect();
        let mut heads = Vec::new();
        for retired in values {
            let fragment = current::lifecycle_fragment(person, retired, &predecessors);
            let id = fragment.root().expect("lifecycle root");
            emit(fragment, output, emitted);
            heads.push(LifecycleHead { id, retired });
        }
        state.lifecycles.insert(person, heads);
    }
    Ok(())
}

fn handle_direct_groups(
    reader: &PileReader,
    delta: &FrozenLegacyDelta,
    global_groups: &BTreeSet<Id>,
    state: &mut ReplayState,
    output: &mut Fragment,
    emitted: &mut TribleSet,
) -> Result<()> {
    let declared: BTreeSet<Id> = entities_with(&delta.facts, metadata::tag.id())
        .into_iter()
        .filter(|entity| {
            tags(&delta.facts, *entity)
                .map(|v| v.contains(&KIND_GROUP))
                .unwrap_or(false)
        })
        .collect();
    let mut changed: BTreeSet<Id> = delta
        .facts
        .iter()
        .filter(|fact| {
            global_groups.contains(fact.e())
                && (fact.a() == &metadata::name.id() || fact.a() == &group::member.id())
        })
        .map(|fact| *fact.e())
        .collect();
    changed.extend(declared.iter().copied());
    for group_id in changed {
        let bases = state.groups.get(&group_id).cloned().unwrap_or_default();
        if bases.is_empty() && !declared.contains(&group_id) {
            bail!("legacy group facts precede group declaration {group_id:X}");
        }
        let predecessor_ids: Vec<_> = bases.iter().map(|head| head.id).collect();
        let old_names: BTreeSet<String> = bases.iter().map(|head| head.data.name.clone()).collect();
        let names = longs(reader, &delta.facts, group_id, &metadata::name)?;
        let choices = if names.is_empty() { old_names } else { names };
        if bases.is_empty() {
            emit(
                entity! { ExclusiveId::force_ref(&group_id) @ metadata::tag: &KIND_GROUP },
                output,
                emitted,
            );
        }
        if choices.is_empty() {
            let snapshot_in_same_delta = entities_with(&delta.facts, group::snapshot_of.id())
                .into_iter()
                .map(|snapshot| ids(&delta.facts, snapshot, &group::snapshot_of))
                .collect::<Result<Vec<_>>>()?
                .iter()
                .any(|anchors| anchors.contains(&group_id));
            if snapshot_in_same_delta {
                continue;
            }
            bail!("legacy group {group_id:X} has no name or initial snapshot");
        }
        let additions = ids(&delta.facts, group_id, &group::member)?;
        let inherited: BTreeSet<Id> = bases
            .iter()
            .flat_map(|head| head.data.members.iter().copied())
            .collect();
        let members: BTreeSet<Id> = inherited.union(&additions).copied().collect();
        for member in &members {
            if !state.profiles.contains_key(member) {
                bail!("legacy group {group_id:X} names person {member:X} before declaration");
            }
        }
        let mut heads = Vec::new();
        for name in choices {
            let fragment = current::group_snapshot_fragment(
                group_id,
                name.clone(),
                &members.iter().copied().collect::<Vec<_>>(),
                &predecessor_ids,
            )?;
            let id = fragment.root().expect("group root");
            emit(fragment, output, emitted);
            heads.push(GroupHead {
                id,
                data: GroupData {
                    name,
                    members: members.clone(),
                },
            });
        }
        dedup(&mut heads);
        state.groups.insert(group_id, heads);
    }
    Ok(())
}

fn handle_snapshot_groups(
    reader: &PileReader,
    delta: &FrozenLegacyDelta,
    state: &mut ReplayState,
    output: &mut Fragment,
    emitted: &mut TribleSet,
) -> Result<()> {
    let mut by_group = BTreeMap::<Id, Vec<GroupHead>>::new();
    let mut pending = entities_with(&delta.facts, group::snapshot_of.id());
    let mut superseded_in_delta = BTreeSet::new();
    while !pending.is_empty() {
        let mut ready = None;
        for &old in &pending {
            let old_predecessors = ids(&delta.facts, old, &metadata::supersedes)?;
            if old_predecessors
                .iter()
                .all(|predecessor| state.old_group_ids.contains_key(predecessor))
            {
                ready = Some((old, old_predecessors));
                break;
            }
        }
        let Some((old, old_predecessors)) = ready else {
            bail!("legacy group snapshot delta has a cyclic or unavailable predecessor");
        };
        pending.remove(&old);
        let group_ids = ids(&delta.facts, old, &group::snapshot_of)?;
        let group_id = *group_ids
            .iter()
            .next()
            .ok_or_else(|| anyhow!("legacy group snapshot {old:X} has no anchor"))?;
        let names = longs(reader, &delta.facts, old, &metadata::name)?;
        let name = names
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("legacy group snapshot {old:X} has no name"))?;
        let mut members = ids(&delta.facts, old, &group::member)?;
        for member in &members {
            if !state.profiles.contains_key(member) {
                bail!("legacy group snapshot {old:X} names person {member:X} before declaration");
            }
        }
        let predecessors: Vec<Id> = if old_predecessors.is_empty() {
            state
                .groups
                .get(&group_id)
                .into_iter()
                .flatten()
                .map(|head| head.id)
                .collect()
        } else {
            old_predecessors
                .iter()
                .map(|predecessor| {
                    state
                        .old_group_ids
                        .get(predecessor)
                        .copied()
                        .ok_or_else(|| {
                            anyhow!(
                                "legacy group snapshot {old:X} supersedes unmapped {predecessor:X}"
                            )
                        })
                })
                .collect::<Result<_>>()?
        };
        if predecessors.len() > 1 {
            let mut joined = BTreeSet::new();
            for predecessor in &predecessors {
                let snapshot = current::group_snapshot(emitted, *predecessor)
                    .with_context(|| format!("read replayed group predecessor {predecessor:X}"))?;
                if snapshot.group != group_id {
                    bail!("legacy group snapshot {old:X} maps a predecessor from another group");
                }
                joined.extend(snapshot.members);
            }
            members = joined;
        }
        superseded_in_delta.extend(predecessors.iter().copied());
        let fragment = current::group_snapshot_fragment(
            group_id,
            name.clone(),
            &members.iter().copied().collect::<Vec<_>>(),
            &predecessors,
        )?;
        let id = fragment.root().expect("group root");
        emit(fragment, output, emitted);
        if let Some(previous) = state.old_group_ids.insert(old, id) {
            if previous != id {
                bail!("legacy group snapshot {old:X} remapped twice");
            }
        }
        by_group.entry(group_id).or_default().push(GroupHead {
            id,
            data: GroupData { name, members },
        });
    }
    for (group_id, mut heads) in by_group {
        heads.retain(|head| !superseded_in_delta.contains(&head.id));
        dedup(&mut heads);
        state.groups.insert(group_id, heads);
    }
    Ok(())
}

fn handle_identity(
    delta: &FrozenLegacyDelta,
    state: &mut ReplayState,
    output: &mut Fragment,
    emitted: &mut TribleSet,
) -> Result<()> {
    let mut updates = BTreeMap::<(Id, Id), BTreeSet<bool>>::new();
    for fact in &delta.facts {
        let values: Option<&[bool]> = if fact.a() == &legacy::same_as.id() {
            Some(&[true])
        } else if fact.a() == &legacy::distinct_from.id() {
            Some(&[false])
        } else if fact.a() == &legacy::review_candidate.id() {
            Some(&[false, true])
        } else {
            None
        };
        let Some(values) = values else {
            continue;
        };
        let other: Id = (*fact.v::<inlineencodings::GenId>())
            .try_from_inline()
            .map_err(|error| anyhow!("decode legacy identity endpoint: {error:?}"))?;
        let endpoints = pair(*fact.e(), other);
        if !state.profiles.contains_key(&endpoints.0) || !state.profiles.contains_key(&endpoints.1)
        {
            bail!("legacy identity edge names a person before declaration");
        }
        updates.entry(endpoints).or_default().extend(values);
    }
    for (endpoints, values) in updates {
        let bases = state.verdicts.get(&endpoints).cloned().unwrap_or_default();
        let predecessors: Vec<_> = bases.iter().map(|head| head.id).collect();
        let mut heads = Vec::new();
        for same in values {
            let fragment =
                current::identity_verdict_fragment(endpoints.0, endpoints.1, same, &predecessors)?;
            let id = fragment.root().expect("identity root");
            emit(fragment, output, emitted);
            heads.push(VerdictHead { id, same });
        }
        state.verdicts.insert(endpoints, heads);
    }
    Ok(())
}

/// Preserve each authored legacy fragment and partition canonical Relations
/// shadows over the exact authored commits.
fn rewrite_relations_commits(
    branch: &FrozenLegacyBranch,
    authored: &[ProjectedLegacyCommit],
    reader: &PileReader,
) -> Result<PartitionedRelationsRewrite> {
    let mut authored_by_commit = BTreeMap::<[u8; 32], &ProjectedLegacyCommit>::new();
    for commit in authored {
        if commit.source.branch != branch.branch || commit.source.pin != branch.pin {
            bail!("Relations authored commit belongs to a different frozen branch");
        }
        if authored_by_commit
            .insert(commit.source.commit.raw, commit)
            .is_some()
        {
            bail!("Relations authored input repeats a legacy commit");
        }
    }
    let expected_authored: BTreeSet<_> = branch
        .deltas
        .iter()
        .filter(|delta| delta.is_authored())
        .map(|delta| delta.commit.raw)
        .collect();
    if authored_by_commit.keys().copied().collect::<BTreeSet<_>>() != expected_authored {
        bail!("Relations authored commits do not exactly cover the frozen authored deltas");
    }

    let mut source_union = TribleSet::new();
    for delta in &branch.deltas {
        source_union += delta.facts.clone();
    }
    let mut authored_union = TribleSet::new();
    for commit in authored {
        authored_union += commit.content.facts().clone();
    }
    if authored_union != source_union {
        bail!("projected Relations authored facts differ from the frozen repository DAG");
    }
    validate_legacy_catalog(reader, &source_union)?;
    validate_immutable_source_shapes(branch, &source_union)?;
    let global_people: BTreeSet<Id> = source_union
        .iter()
        .filter(|fact| fact.a() == &metadata::tag.id())
        .filter_map(|fact| {
            let value: Result<Id, _> = (*fact.v::<inlineencodings::GenId>()).try_from_inline();
            value
                .ok()
                .filter(|kind| kind == &KIND_PERSON_ID)
                .map(|_| *fact.e())
        })
        .collect();
    let global_groups: BTreeSet<Id> = source_union
        .iter()
        .filter(|fact| fact.a() == &metadata::tag.id())
        .filter_map(|fact| {
            let value: Result<Id, _> = (*fact.v::<inlineencodings::GenId>()).try_from_inline();
            value
                .ok()
                .filter(|kind| kind == &KIND_GROUP)
                .map(|_| *fact.e())
        })
        .collect();

    let mut states = BTreeMap::<[u8; 32], ReplayState>::new();
    let mut output_by_commit = BTreeMap::<[u8; 32], Fragment>::new();
    // Source assertions already belong to their exact authored partitions.
    // Treat them as emitted before placing additive shadows so a later
    // canonical record cannot physically re-home an overlapping assertion.
    let mut emitted = source_union.clone();
    for delta in &branch.deltas {
        let mut state = merge_parent_states(delta, &states)?;
        let mut output = if delta.is_authored() {
            authored_by_commit[&delta.commit.raw].content.clone()
        } else {
            Fragment::empty()
        };
        if delta.is_authored() {
            handle_person_profiles(
                reader,
                delta,
                &global_people,
                &mut state,
                &mut output,
                &mut emitted,
            )?;
            handle_lifecycle_events(delta, &mut state, &mut output, &mut emitted)?;
            handle_direct_groups(
                reader,
                delta,
                &global_groups,
                &mut state,
                &mut output,
                &mut emitted,
            )?;
            handle_snapshot_groups(reader, delta, &mut state, &mut output, &mut emitted)?;
            handle_anchor_provenance(
                delta,
                &global_people,
                &global_groups,
                &mut output,
                &mut emitted,
            )?;
            handle_identity(delta, &mut state, &mut output, &mut emitted)?;
            output_by_commit.insert(delta.commit.raw, output);
        }
        states.insert(delta.commit.raw, state);
    }

    let final_state = branch
        .head
        .and_then(|head| states.get(&head.raw))
        .ok_or_else(|| anyhow!("legacy Relations branch has no replayable head"))?;
    if current_people(final_state) != global_people {
        bail!("Relations replay did not preserve every stable person anchor");
    }
    if final_state.groups.keys().copied().collect::<BTreeSet<_>>() != global_groups {
        bail!("Relations replay did not preserve every stable group anchor");
    }

    let mut partitions = Vec::with_capacity(authored.len());
    let mut complete = Fragment::empty();
    let mut union = TribleSet::new();
    for delta in branch.deltas.iter().filter(|delta| delta.is_authored()) {
        let source = authored_by_commit[&delta.commit.raw];
        let content = output_by_commit
            .remove(&delta.commit.raw)
            .unwrap_or_else(Fragment::empty);
        union += content.facts().clone();
        complete += content.clone();
        let mut preserved = source.content.clone();
        preserved.describe_with(source.metadata.clone());
        partitions.push(RelationsCommitPartition {
            source: source.source,
            content,
            metadata: source.metadata.clone(),
            preserved,
        });
    }
    let canonical_additions = emitted.difference(&source_union);
    let mut expected = source_union.clone();
    expected += canonical_additions.clone();
    if union != expected {
        bail!("Relations rewrite is not exactly legacy facts union canonical shadows");
    }
    current::validate_catalog_union(reader, &TribleSet::new(), &complete)
        .context("validate reconstructed Relations catalog and attachments")?;
    Ok(PartitionedRelationsRewrite {
        commits: partitions,
        original: source_union,
        additions: canonical_additions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::{self, File};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace::core::inline::encodings::hash::Handle;
    use triblespace::core::repo::{BlobStore, BlobStoreGet, PinStore, Repository};
    use triblespace::macros::{find, pattern};
    use triblespace::prelude::TryToInline;

    use crate::collection_cutover::{
        discover_target, freeze_source, initialize_signer, open_pile_strict,
    };

    type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-relations-cutover-{}-{serial}",
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
        let epoch = Epoch::from_unix_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn person(person: Id, label: &str) -> Fragment {
        let mut fragment = Fragment::empty();
        let label = fragment.put(label.to_owned());
        fragment += entity! { ExclusiveId::force_ref(&person) @
            metadata::tag: &KIND_PERSON_ID,
            metadata::name: label,
        };
        fragment
    }

    fn event(person: Id, retired: bool, second: f64) -> Fragment {
        let kind = if retired {
            KIND_RETIRE_ID
        } else {
            KIND_UNRETIRE_ID
        };
        entity! {
            metadata::tag: &kind,
            legacy::subject: &person,
            metadata::created_at: at(second),
        }
    }

    fn old_group_snapshot(
        snapshot: Id,
        group_id: Id,
        name: &str,
        members: &[Id],
        predecessors: &[Id],
    ) -> Fragment {
        let mut fragment = Fragment::empty();
        let name = fragment.put(name.to_owned());
        fragment += entity! { ExclusiveId::force_ref(&snapshot) @
            group::snapshot_of: &group_id,
            metadata::name: name,
            group::member*: members.iter(),
            metadata::supersedes*: predecessors.iter(),
        };
        fragment
    }

    struct Fixture {
        _directory: TestDirectory,
        source: PathBuf,
        target: PathBuf,
        key: PathBuf,
        branch: Id,
        ada: Id,
        other: Id,
        group: Id,
        old_group_snapshots: [Id; 3],
        created_person: IntervalValue,
        created_group: IntervalValue,
    }

    fn fixture() -> Fixture {
        let directory = TestDirectory::new();
        let source = directory.0.join("legacy.pile");
        let target = directory.0.join("target.pile");
        let key = directory.0.join("target.key");
        File::create(&source).unwrap();
        File::create(&target).unwrap();

        let pile = open_pile_strict(&source).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0x91; 32]), Fragment::empty()).unwrap();
        let branch = *repository.create_branch(LEGACY_BRANCH_NAME, None).unwrap();
        let ada = Id::new([0x92; 16]).unwrap();
        let other = Id::new([0x93; 16]).unwrap();
        let group = Id::new([0x94; 16]).unwrap();
        let created_person = at(10.0);
        let created_group = at(20.0);

        let mut root = person(ada, "ada") + person(other, "other");
        let group_name = root.put("crew".to_owned());
        root += entity! { ExclusiveId::force_ref(&ada) @
            legacy::source: "import",
            metadata::created_at: created_person,
            legacy::review_candidate: &other,
        };
        root += entity! { ExclusiveId::force_ref(&group) @
            metadata::tag: &KIND_GROUP,
            metadata::name: group_name,
            metadata::created_at: created_group,
        };
        let mut root_workspace = repository.pull(branch).unwrap();
        root_workspace.commit_with_metadata(
            root,
            entity! { metadata::description: "legacy root metadata" },
            "root",
        );
        repository.push(&mut root_workspace).unwrap();

        // Two workspaces from one base produce two authored children and one
        // contentless repository merge when the second push resolves conflict.
        let mut left = repository.pull(branch).unwrap();
        let mut right = repository.pull(branch).unwrap();
        let old_left = Id::new([0x95; 16]).unwrap();
        let old_right = Id::new([0x96; 16]).unwrap();
        left.commit(
            event(ada, true, 30.0) + old_group_snapshot(old_left, group, "crew", &[ada], &[]),
            "left",
        );
        right.commit(
            event(ada, false, 40.0) + old_group_snapshot(old_right, group, "crew", &[other], &[]),
            "right",
        );
        repository.push(&mut left).unwrap();
        repository.push(&mut right).unwrap();

        // Historical multi-parent records were not required to carry the
        // predecessor member union. The transform derives that join rather
        // than reproducing a lossy empty member set.
        let old_join = Id::new([0x97; 16]).unwrap();
        let mut joined = repository.pull(branch).unwrap();
        joined.commit(
            old_group_snapshot(old_join, group, "crew", &[], &[old_left, old_right]),
            "group join",
        );
        repository.push(&mut joined).unwrap();
        repository.close().unwrap();
        initialize_signer(&target, Some(&key)).unwrap();

        Fixture {
            _directory: directory,
            source,
            target,
            key,
            branch,
            ada,
            other,
            group,
            old_group_snapshots: [old_left, old_right, old_join],
            created_person,
            created_group,
        }
    }

    fn target_facts(fixture: &Fixture) -> (TribleSet, TribleSet, usize) {
        let mut pile = open_pile_strict(&fixture.target).unwrap();
        let target = discover_target(&mut pile, schema::DEFAULT_SCOPE_ID).unwrap();
        let commit_count = target.commits().len();
        let reader = pile.reader().unwrap();
        let mut facts = TribleSet::new();
        let mut metadata_facts = TribleSet::new();
        for commit in target.commits() {
            facts += reader
                .get::<TribleSet, SimpleArchive>(Handle::from_hash(commit.data()))
                .unwrap();
            metadata_facts += reader
                .get::<TribleSet, SimpleArchive>(commit.metadata())
                .unwrap();
        }
        current::validate_catalog(&reader, &facts).unwrap();
        pile.close().unwrap();
        (facts, metadata_facts, commit_count)
    }

    #[test]
    fn plan_is_strictly_additive_and_preserves_forks_provenance_and_groups() {
        let fixture = fixture();
        let frozen = freeze_source(&fixture.source).unwrap();
        let plan = plan(&frozen).unwrap();

        plan.verify_conservation().unwrap();
        assert!(frozen.legacy_pins().contains(&plan.source_pin()));
        assert_eq!(plan.report().authored_commits, 4);
        assert_eq!(plan.commits().len(), 4);
        assert_eq!(plan.report().original_facts, plan.original_facts().len());
        assert_eq!(
            plan.report().preserved_original_facts,
            plan.original_facts().len()
        );
        assert_eq!(
            plan.report().added_canonical_facts,
            plan.added_facts().len()
        );
        assert_eq!(
            plan.report().materialized_facts,
            plan.original_facts().len() + plan.added_facts().len()
        );
        assert_eq!(plan.report().people, 2);
        assert_eq!(plan.report().groups, 1);
        for commit in plan.commits() {
            let mut retained = commit.fragment.clone();
            retained += commit.preserved_fragment().clone();
            assert_eq!(retained, commit.fragment);
        }

        let facts = plan.materialized_facts();
        for fact in plan.original_facts() {
            assert!(facts.contains(fact));
        }
        for legacy_id in fixture.old_group_snapshots {
            assert!(plan
                .original_facts()
                .iter()
                .any(|fact| fact.e() == &legacy_id));
            assert!(facts.iter().any(|fact| fact.e() == &legacy_id));
            assert!(current::group_snapshot(&facts, legacy_id).is_err());
        }
        let overlapping_anchor_fact = entity! { ExclusiveId::force_ref(&fixture.ada) @
            metadata::tag: &KIND_PERSON_ID,
        }
        .facts()
        .iter()
        .copied()
        .next()
        .unwrap();
        assert!(plan.original_facts().contains(&overlapping_anchor_fact));
        assert!(!plan.added_facts().contains(&overlapping_anchor_fact));
        for fact in current::person_provenance_fragment(
            fixture.ada,
            vec!["import".to_owned()],
            &[fixture.created_person],
        )
        .unwrap()
        .facts()
        {
            assert!(plan.original_facts().contains(fact));
            assert!(!plan.added_facts().contains(fact));
        }
        assert_eq!(
            current::person_sources(&facts, fixture.ada).unwrap(),
            ["import"]
        );
        assert_eq!(
            current::creation_observations(&facts, fixture.ada),
            [fixture.created_person]
        );
        assert_eq!(
            current::creation_observations(&facts, fixture.group),
            [fixture.created_group]
        );
        assert!(matches!(
            current::lifecycle_head(&facts, fixture.ada).unwrap(),
            current::Head::Forked(heads) if heads.len() == 2
        ));
        assert!(matches!(
            current::identity_head(&facts, fixture.ada, fixture.other).unwrap(),
            current::Head::Forked(heads) if heads.len() == 2
        ));
        let group = current::current_group(&facts, fixture.group).unwrap();
        assert_eq!(
            group.members,
            vec![
                fixture.ada.min(fixture.other),
                fixture.ada.max(fixture.other)
            ]
        );
        assert_eq!(group.predecessors.len(), 2);
    }

    #[test]
    fn later_shadow_does_not_duplicate_a_fact_from_its_authored_source_commit() {
        let fixture = fixture();

        // Extend the fixture with a legacy snapshot whose random-id-era
        // subject deliberately equals the intrinsic id of its successor.
        // Its source record is an exact subset of that later canonical
        // record, so the union remains a valid intrinsic catalog while the
        // physical commit partition exposes any cross-commit duplication.
        let root = current::group_snapshot_fragment(fixture.group, "crew", &[], &[])
            .unwrap()
            .root()
            .unwrap();
        let left = current::group_snapshot_fragment(fixture.group, "crew", &[fixture.ada], &[root])
            .unwrap()
            .root()
            .unwrap();
        let right =
            current::group_snapshot_fragment(fixture.group, "crew", &[fixture.other], &[root])
                .unwrap()
                .root()
                .unwrap();
        let members = [
            fixture.ada.min(fixture.other),
            fixture.ada.max(fixture.other),
        ];
        let joined =
            current::group_snapshot_fragment(fixture.group, "crew", &members, &[left, right])
                .unwrap()
                .root()
                .unwrap();
        let predecessor =
            current::group_snapshot_fragment(fixture.group, "crew", &members, &[joined])
                .unwrap()
                .root()
                .unwrap();
        let successor =
            current::group_snapshot_fragment(fixture.group, "crew", &members, &[predecessor])
                .unwrap();
        let successor_id = successor.root().unwrap();
        let later_legacy_id = Id::new([0xA9; 16]).unwrap();

        let pile = open_pile_strict(&fixture.source).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0x91; 32]), Fragment::empty()).unwrap();
        let mut source_owner = repository.pull(fixture.branch).unwrap();
        source_owner.commit(
            old_group_snapshot(successor_id, fixture.group, "crew", &members, &[]),
            "source-resident future shadow subset",
        );
        repository.push(&mut source_owner).unwrap();
        let mut later = repository.pull(fixture.branch).unwrap();
        later.commit(
            old_group_snapshot(
                later_legacy_id,
                fixture.group,
                "crew",
                &members,
                &[successor_id],
            ),
            "later canonical shadow",
        );
        repository.push(&mut later).unwrap();
        repository.close().unwrap();

        let frozen = freeze_source(&fixture.source).unwrap();
        let plan = plan(&frozen).unwrap();
        plan.verify_conservation().unwrap();

        let overlap = successor
            .facts()
            .iter()
            .find(|fact| fact.a() == &group::snapshot_of.id())
            .copied()
            .unwrap();
        let source_owners: Vec<_> = plan
            .commits()
            .iter()
            .enumerate()
            .filter(|(_, commit)| commit.preserved_fragment().facts().contains(&overlap))
            .map(|(index, _)| index)
            .collect();
        let physical_owners: Vec<_> = plan
            .commits()
            .iter()
            .enumerate()
            .filter(|(_, commit)| commit.fragment.facts().contains(&overlap))
            .map(|(index, _)| index)
            .collect();
        assert_eq!(source_owners.len(), 1);
        assert_eq!(physical_owners, source_owners);

        let later_commit = plan
            .commits()
            .iter()
            .find(|commit| {
                commit
                    .preserved_fragment()
                    .facts()
                    .iter()
                    .any(|fact| fact.e() == &later_legacy_id)
            })
            .unwrap();
        assert!(!later_commit.fragment.facts().contains(&overlap));
        let canonical_addition = successor
            .facts()
            .iter()
            .find(|fact| fact.a() == &metadata::supersedes.id())
            .copied()
            .unwrap();
        assert!(later_commit.fragment.facts().contains(&canonical_addition));

        let facts = plan.materialized_facts();
        let snapshot = current::group_snapshot(&facts, successor_id).unwrap();
        assert_eq!(snapshot.group, fixture.group);
        assert_eq!(snapshot.members, members);
        assert_eq!(snapshot.predecessors, vec![predecessor]);
        assert_eq!(
            plan.report().materialized_facts,
            plan.original_facts().len() + plan.added_facts().len()
        );
    }

    #[test]
    fn native_publication_is_idempotent_and_never_creates_target_pins() {
        let fixture = fixture();
        let frozen = freeze_source(&fixture.source).unwrap();
        let plan = plan(&frozen).unwrap();
        let first = publish(&frozen, &plan, &fixture.target, Some(&fixture.key)).unwrap();
        let after_first = fs::metadata(&fixture.target).unwrap().len();
        let second = publish(&frozen, &plan, &fixture.target, Some(&fixture.key)).unwrap();
        assert_eq!(first, second);
        assert_eq!(fs::metadata(&fixture.target).unwrap().len(), after_first);

        let mut target = open_pile_strict(&fixture.target).unwrap();
        assert!(target
            .pins()
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
            .is_empty());
        target.close().unwrap();

        let mut source = open_pile_strict(&fixture.source).unwrap();
        let source_pin = plan.source_pin();
        assert_eq!(source.head(source_pin.id).unwrap(), Some(source_pin.value));
        source.close().unwrap();

        let (facts, metadata_facts, commits) = target_facts(&fixture);
        assert_eq!(commits, 4, "contentless merge emits no authored commit");
        assert_eq!(facts, plan.materialized_facts());
        for fact in plan.original_facts() {
            assert!(facts.contains(fact));
        }
        let expected_metadata =
            plan.commits()
                .iter()
                .fold(TribleSet::new(), |mut facts, commit| {
                    facts += commit.fragment.metafacts().clone();
                    facts
                });
        assert_eq!(metadata_facts, expected_metadata);
        let mut target = open_pile_strict(&fixture.target).unwrap();
        let reader = target.reader().unwrap();
        let descriptions: BTreeSet<String> = find!(
            description: Inline<inlineencodings::Handle<LongString>>,
            pattern!(&metadata_facts, [{ _?entity @ metadata::description: ?description }])
        )
        .map(|handle| reader.get::<View<str>, _>(handle).unwrap().to_string())
        .collect();
        assert!(descriptions.contains("legacy root metadata"));
        target.close().unwrap();
    }

    #[test]
    fn provenance_only_orphan_does_not_mint_a_person_anchor() {
        let fixture = fixture();
        let pile = open_pile_strict(&fixture.source).unwrap();
        let orphan = Id::new([0xA8; 16]).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0x91; 32]), Fragment::empty()).unwrap();
        let mut workspace = repository.pull(fixture.branch).unwrap();
        workspace.commit(
            entity! { ExclusiveId::force_ref(&orphan) @ legacy::source: "linkedin" },
            "orphan exhaust",
        );
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();

        let frozen = freeze_source(&fixture.source).unwrap();
        let plan = plan(&frozen).unwrap();
        assert!(!current::person_anchors(&plan.materialized_facts()).contains(&orphan));
        assert!(plan.original_facts().iter().any(|fact| fact.e() == &orphan));
        assert!(plan
            .materialized_facts()
            .iter()
            .any(|fact| fact.e() == &orphan));
    }
}
