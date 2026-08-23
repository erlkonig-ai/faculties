//! Stopped-world rewrite of the historical Body and Senses branches.
//!
//! Both branches predate the current intrinsic-entity hashing epoch. Every
//! historical record is verified under the v1 rule, then captures and intents
//! are reconstructed under the current canonical Body ontology. Historical
//! speech is validated but deliberately excluded for the Voice transform.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::attribute::Attribute;
use triblespace::core::blob::encodings::utf8string::UTF8String;
use triblespace::core::blob::encodings::UnknownBlob;
use triblespace::core::blob::Blob;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::encodings::shortstring::ShortString;
use triblespace::core::inline::{Inline, InlineEncoding};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::core::trible::intrinsic_entity_id_v1;
use triblespace::prelude::*;

use crate::collection_cutover::{
    project_legacy_authored_commits, FrozenLegacyBranch, FrozenSource, LegacyCommitCoordinate,
    LegacyPinCoordinate, ProjectedLegacyCommit,
};
use faculties::body::{
    self, BodyCatalog, CaptureRow, IntentRow, IntervalValue, RawHandle, TextHandle,
};
use faculties::schemas::body::{
    self as schema, KIND_CAPTURE, KIND_INTENT, LEGACY_BODY_BRANCH_NAME, LEGACY_SENSES_BRANCH_NAME,
};
use faculties::storage::{load_signer, open_pile_strict};

/// Historical Body tag for an utterance before Voice became its own faculty.
pub const LEGACY_KIND_UTTERANCE: Id =
    triblespace::macros::id_hex!("B715BF1EEB1904393A7C31A0C1FFDF8C");

/// Exact historical utterance attributes shared with the Voice rewrite.
pub mod legacy_utterance {
    use super::*;

    attributes! {
        "09792243FE6C424FD80D7EF7E48EBAEA" unsafe as pub text: Handle<UTF8String>;
        "33892D142FCB2ED2D40B9724847B3859" unsafe as pub channel: ShortString;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyBodyUtteranceRow {
    pub id: Id,
    pub created_at: IntervalValue,
    pub text: TextHandle,
    pub channel: String,
    pub audio: RawHandle,
    pub mime: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LegacyBodyCatalog {
    pub captures: BTreeMap<Id, CaptureRow>,
    pub intents: BTreeMap<Id, IntentRow>,
    pub utterances: BTreeMap<Id, LegacyBodyUtteranceRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BodyMigrationReport {
    pub authored_commits: usize,
    pub authored_empty_commits: usize,
    pub contentless_merges: usize,
    pub input_fact_occurrences: usize,
    pub input_unique_facts: usize,
    pub output_facts: usize,
    pub legacy_captures: usize,
    pub canonical_captures: usize,
    pub legacy_intents: usize,
    pub canonical_intents: usize,
    pub excluded_utterances: usize,
    pub excluded_utterance_facts: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyMigrationPlan {
    source_pins: [LegacyPinCoordinate; 2],
    commits: Vec<BodyMigrationCommit>,
    original: TribleSet,
    rewritten: TribleSet,
    report: BodyMigrationReport,
}

impl BodyMigrationPlan {
    pub const fn source_pins(&self) -> &[LegacyPinCoordinate; 2] {
        &self.source_pins
    }

    pub fn commits(&self) -> &[BodyMigrationCommit] {
        &self.commits
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    pub const fn report(&self) -> &BodyMigrationReport {
        &self.report
    }

    pub fn materialized_facts(&self) -> TribleSet {
        self.commits
            .iter()
            .flat_map(|commit| commit.fragment.facts().iter().copied())
            .collect()
    }

    pub fn verify_conservation(&self) -> Result<()> {
        if self.materialized_facts() != self.rewritten {
            bail!("planned Body commit partition differs from its canonical rewrite");
        }
        if self.report.authored_commits != self.commits.len()
            || self.report.input_unique_facts != self.original.len()
            || self.report.output_facts != self.rewritten.len()
            || self.report.legacy_captures != self.report.canonical_captures
            || self.report.legacy_intents != self.report.canonical_intents
        {
            bail!("Body migration report disagrees with its planned commits");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PartitionedBodyRewrite {
    content: Fragment,
    commits: Vec<BodyMigrationCommit>,
    report: BodyMigrationReport,
}

/// Plan the complete historical Body and Senses rewrite without mutating the pile.
pub fn plan(source: &FrozenSource) -> Result<BodyMigrationPlan> {
    let body_branch = source
        .legacy_branch(LEGACY_BODY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Body branch"))?;
    let senses_branch = source
        .legacy_branch(LEGACY_SENSES_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Senses branch"))?;

    let mut authored =
        project_legacy_authored_commits(source, &body_branch, validate_legacy_body_payloads)
            .context("project frozen Body authored commits")?;
    authored.extend(
        project_legacy_authored_commits(source, &senses_branch, validate_legacy_body_payloads)
            .context("project frozen Senses authored commits")?,
    );

    let original: TribleSet = authored
        .iter()
        .flat_map(|commit| commit.content.facts().iter().copied())
        .collect();
    let rewritten =
        rewrite_body_authored_commits(&body_branch, &senses_branch, &authored, source.reader())
            .context("rewrite frozen Body and Senses branches")?;

    let plan = BodyMigrationPlan {
        source_pins: [body_branch.pin_coordinate(), senses_branch.pin_coordinate()],
        commits: rewritten.commits,
        original,
        rewritten: rewritten.content.into_facts(),
        report: rewritten.report,
    };
    plan.verify_conservation()?;
    Ok(plan)
}

pub fn publish(
    source: &FrozenSource,
    plan: &BodyMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    for pin in plan.source_pins {
        if !source.legacy_pins().contains(&pin) {
            bail!("Body migration plan does not belong to this frozen source");
        }
    }
    plan.verify_conservation()?;

    crate::write_authority::publish(target, key)
        .context("initialize WRITE authority before Body migration publication")?;

    let signer = load_signer(target, key)?;
    let pile = open_pile_strict(target)?;
    let mut collection = faculties::collection_names::open(pile, schema::DEFAULT_SCOPE_ID, signer);
    let result = (|| {
        let current = collection
            .materialize()
            .context("materialize existing native Body value")?;
        let reader = collection
            .storage_mut()
            .reader()
            .context("open Body publication attachment reader")?;
        let mut staged = Fragment::empty();
        for commit in &plan.commits {
            staged += commit.fragment.clone();
        }
        body::validate_candidate(&reader, &current, &staged)
            .context("preflight complete post-migration Body union")?;

        plan.commits
            .iter()
            .map(|commit| {
                collection.commit(commit.fragment.clone()).with_context(|| {
                    format!(
                        "publish Body commit projected from {}",
                        hex::encode_upper(commit.source.commit.raw)
                    )
                })
            })
            .collect()
    })();
    finish_pile(collection.into_storage(), result)
}

pub(crate) fn load_legacy_body_utterance(
    reader: &PileReader,
    facts: &TribleSet,
    id: Id,
) -> Result<LegacyBodyUtteranceRow> {
    let row = LegacyBodyUtteranceRow {
        id,
        created_at: exactly_one(
            id,
            "metadata::created_at",
            inline_values(facts, id, &metadata::created_at),
        )?,
        text: exactly_one(
            id,
            "legacy utterance text",
            inline_values(facts, id, &legacy_utterance::text),
        )?,
        channel: exactly_one(
            id,
            "legacy utterance channel",
            short_values(facts, id, &legacy_utterance::channel)?,
        )?,
        audio: exactly_one(
            id,
            "legacy utterance audio",
            inline_values(facts, id, &schema::capture::frame),
        )?,
        mime: exactly_one(
            id,
            "legacy utterance MIME",
            short_values(facts, id, &schema::capture::mime)?,
        )?,
    };
    validate_point("legacy utterance creation time", row.created_at)?;
    if !matches!(row.channel.as_str(), "computer" | "body") {
        bail!(
            "legacy Body utterance {id:X} has unknown channel {:?}",
            row.channel
        );
    }
    if row.mime != "audio/wav" {
        bail!(
            "legacy Body utterance {id:X} has MIME {:?}; expected audio/wav",
            row.mime
        );
    }

    let exact = body::entity_facts(facts, id);
    let expected = legacy_utterance_record(&row);
    require_same_record_values("utterance", id, &exact, expected.facts())?;
    require_v1_intrinsic("utterance", id, &exact)?;

    let _: View<str> = reader
        .get(row.text)
        .with_context(|| format!("read text of legacy Body utterance {id:X}"))?;
    let _: anybytes::Bytes = reader
        .get(row.audio)
        .with_context(|| format!("read audio of legacy Body utterance {id:X}"))?;
    Ok(row)
}

pub(crate) fn load_legacy_body_catalog(
    reader: &PileReader,
    facts: &TribleSet,
) -> Result<LegacyBodyCatalog> {
    validate_legacy_body_payloads(reader, facts)?;
    let mut catalog = LegacyBodyCatalog::default();
    let subjects: BTreeSet<Id> = facts.iter().map(|fact| *fact.e()).collect();
    for id in subjects {
        let tags: BTreeSet<Id> =
            find!(kind: Id, pattern!(facts, [{ id @ metadata::tag: ?kind }])).collect();
        let kind = match tags.iter().copied().collect::<Vec<_>>().as_slice() {
            [kind] => *kind,
            [] => bail!("legacy Body entity {id:X} has no kind tag"),
            _ => bail!("legacy Body entity {id:X} has several kind tags: {tags:?}"),
        };
        match kind {
            KIND_CAPTURE => {
                let row = body::decode_capture(facts, id)
                    .with_context(|| format!("decode legacy Body capture {id:X}"))?;
                let exact = body::entity_facts(facts, id);
                let expected = body::capture_record(&row);
                require_same_record_values("capture", id, &exact, expected.facts())?;
                require_v1_intrinsic("capture", id, &exact)?;
                catalog.captures.insert(id, row);
            }
            KIND_INTENT => {
                let row = body::decode_intent(facts, id)
                    .with_context(|| format!("decode legacy Body intent {id:X}"))?;
                let exact = body::entity_facts(facts, id);
                let expected = body::intent_record(&row);
                require_same_record_values("intent", id, &exact, expected.facts())?;
                require_v1_intrinsic("intent", id, &exact)?;
                catalog.intents.insert(id, row);
            }
            LEGACY_KIND_UTTERANCE => {
                let row = load_legacy_body_utterance(reader, facts, id)?;
                catalog.utterances.insert(id, row);
            }
            _ => bail!("legacy Body entity {id:X} has unknown kind {kind:X}"),
        }
    }
    Ok(catalog)
}

fn rewrite_body_authored_commits(
    body_branch: &FrozenLegacyBranch,
    senses_branch: &FrozenLegacyBranch,
    authored: &[ProjectedLegacyCommit],
    reader: &PileReader,
) -> Result<PartitionedBodyRewrite> {
    let mut ordered: Vec<&ProjectedLegacyCommit> = authored.iter().collect();
    ordered.sort_unstable_by_key(|commit| commit.source);
    for pair in ordered.windows(2) {
        if pair[0].source == pair[1].source {
            bail!(
                "Body authored input repeats legacy commit {}",
                hex::encode_upper(pair[0].source.commit.raw)
            );
        }
    }

    let expected_sources: BTreeSet<LegacyCommitCoordinate> = [body_branch, senses_branch]
        .into_iter()
        .flat_map(|branch| {
            branch
                .deltas
                .iter()
                .filter(|delta| delta.is_authored())
                .map(|delta| LegacyCommitCoordinate {
                    branch: branch.branch,
                    pin: branch.pin,
                    commit: delta.commit,
                })
        })
        .collect();
    let actual_sources: BTreeSet<LegacyCommitCoordinate> =
        ordered.iter().map(|commit| commit.source).collect();
    if actual_sources != expected_sources {
        bail!(
            "Body authored commits do not exactly cover both frozen branches (expected {}, found {})",
            expected_sources.len(),
            actual_sources.len()
        );
    }

    let mut union = TribleSet::new();
    for commit in &ordered {
        union += commit.content.facts().clone();
    }
    let input_fact_occurrences: usize = ordered
        .iter()
        .map(|commit| commit.content.facts().len())
        .sum();
    let legacy = load_legacy_body_catalog(reader, &union)
        .context("validate historical Body/Senses union")?;

    // Body deliberately excludes pre-extraction speech because Voice owns its
    // reconstruction. Voice consumes the Body pin, not Senses, so accepting a
    // Senses-only utterance here would strand a validated record between the
    // two collection plans even though aggregate pin coverage still passed.
    let body_authored = ordered
        .iter()
        .copied()
        .filter(|commit| {
            commit.source.branch == body_branch.branch && commit.source.pin == body_branch.pin
        })
        .collect::<Vec<_>>();
    for old_id in legacy.utterances.keys() {
        let old_facts = body::entity_facts(&union, *old_id);
        complete_record_witness(
            "pre-extraction Voice utterance on the Body branch",
            *old_id,
            &old_facts,
            &body_authored,
        )?;
    }

    let mut output_by_source: BTreeMap<LegacyCommitCoordinate, Fragment> = actual_sources
        .iter()
        .copied()
        .map(|source| (source, Fragment::empty()))
        .collect();
    let mut canonical_owners = BTreeMap::<Id, Id>::new();

    for (old_id, row) in &legacy.captures {
        let old_facts = body::entity_facts(&union, *old_id);
        let owner = complete_record_witness("capture", *old_id, &old_facts, &ordered)?;
        let mut canonical = body::capture_record(row);
        stage_capture_payloads(reader, &mut canonical, row)
            .with_context(|| format!("stage payloads for legacy Body capture {old_id:X}"))?;
        let new_id = canonical
            .root()
            .expect("canonical Body capture has one root");
        if let Some(previous) = canonical_owners.insert(new_id, *old_id) {
            bail!(
                "legacy Body records {previous:X} and {old_id:X} collapse to canonical identity {new_id:X}"
            );
        }
        *output_by_source
            .get_mut(&owner)
            .expect("complete witness has a partition slot") += canonical;
    }

    for (old_id, row) in &legacy.intents {
        let old_facts = body::entity_facts(&union, *old_id);
        let owner = complete_record_witness("intent", *old_id, &old_facts, &ordered)?;
        let mut canonical = body::intent_record(row);
        stage_unknown(reader, &mut canonical, row.text.transmute())
            .with_context(|| format!("stage text for legacy Body intent {old_id:X}"))?;
        let new_id = canonical
            .root()
            .expect("canonical Body intent has one root");
        if let Some(previous) = canonical_owners.insert(new_id, *old_id) {
            bail!(
                "legacy Body records {previous:X} and {old_id:X} collapse to canonical identity {new_id:X}"
            );
        }
        *output_by_source
            .get_mut(&owner)
            .expect("complete witness has a partition slot") += canonical;
    }

    let mut content = Fragment::empty();
    let mut seen_facts = TribleSet::new();
    let mut commits = Vec::with_capacity(ordered.len());
    for authored in ordered {
        let partition = output_by_source
            .remove(&authored.source)
            .expect("every authored source has a partition slot");
        let overlap = seen_facts.intersect(partition.facts());
        if !overlap.is_empty() {
            bail!(
                "canonical Body commit partition overlaps by {} fact(s)",
                overlap.len()
            );
        }
        seen_facts += partition.facts().clone();
        content += partition.clone();

        let mut fragment = partition;
        fragment.describe_with(authored.metadata.clone());
        commits.push(BodyMigrationCommit {
            source: authored.source,
            fragment,
        });
    }
    if !output_by_source.is_empty() || seen_facts != *content.facts() {
        bail!("canonical Body commit partition does not equal the global rewrite");
    }

    let catalog = body::validate_candidate(reader, &TribleSet::new(), &content)
        .context("validate canonical Body rewrite")?;
    require_all_payloads_staged(&content, &catalog)?;
    if catalog.captures.len() != legacy.captures.len()
        || catalog.intents.len() != legacy.intents.len()
    {
        bail!("Body capture or intent conservation failed");
    }
    if content.facts().iter().any(is_legacy_utterance_fact) {
        bail!("canonical Body output retains pre-extraction Voice vocabulary");
    }

    let excluded_utterance_facts: usize = legacy
        .utterances
        .keys()
        .map(|id| body::entity_facts(&union, *id).len())
        .sum();
    let report = BodyMigrationReport {
        authored_commits: commits.len(),
        authored_empty_commits: authored_empty_count(body_branch, senses_branch),
        contentless_merges: [body_branch, senses_branch]
            .into_iter()
            .flat_map(|branch| branch.deltas.iter())
            .filter(|delta| !delta.is_authored())
            .count(),
        input_fact_occurrences,
        input_unique_facts: union.len(),
        output_facts: content.facts().len(),
        legacy_captures: legacy.captures.len(),
        canonical_captures: catalog.captures.len(),
        legacy_intents: legacy.intents.len(),
        canonical_intents: catalog.intents.len(),
        excluded_utterances: legacy.utterances.len(),
        excluded_utterance_facts,
    };

    Ok(PartitionedBodyRewrite {
        content,
        commits,
        report,
    })
}

fn authored_empty_count(
    body_branch: &FrozenLegacyBranch,
    senses_branch: &FrozenLegacyBranch,
) -> usize {
    [body_branch, senses_branch]
        .into_iter()
        .flat_map(|branch| branch.deltas.iter())
        .filter(|delta| delta.is_authored() && delta.facts.is_empty())
        .count()
}

pub(crate) fn validate_legacy_body_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts {
        if fact.a() == &schema::capture::frame.id() {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::RawBytes>>();
            let _: anybytes::Bytes = reader.get(handle).with_context(|| {
                format!(
                    "strictly read historical Body frame {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        } else if fact.a() == &schema::intent::text.id()
            || fact.a() == &schema::capture::note.id()
            || fact.a() == &schema::capture::pose.id()
            || fact.a() == &legacy_utterance::text.id()
            || fact.a() == &metadata::description.id()
        {
            let handle = *fact.v::<Handle<UTF8String>>();
            let _: View<str> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read historical Body text {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

fn legacy_utterance_record(row: &LegacyBodyUtteranceRow) -> Fragment {
    entity! {
        metadata::tag: &LEGACY_KIND_UTTERANCE,
        metadata::created_at: row.created_at,
        legacy_utterance::text: row.text,
        legacy_utterance::channel: row.channel.as_str(),
        schema::capture::frame: row.audio,
        schema::capture::mime: row.mime.as_str(),
    }
}

fn record_values(facts: &TribleSet) -> BTreeSet<(Id, [u8; 32])> {
    facts
        .iter()
        .map(|fact| (*fact.a(), fact.v::<inlineencodings::R256>().raw))
        .collect()
}

fn require_same_record_values(
    kind: &str,
    id: Id,
    actual: &TribleSet,
    expected: &TribleSet,
) -> Result<()> {
    if record_values(actual) != record_values(expected) {
        bail!("legacy Body {kind} {id:X} has facts outside its exact historical record");
    }
    Ok(())
}

fn require_v1_intrinsic(kind: &str, id: Id, facts: &TribleSet) -> Result<()> {
    if facts.iter().any(|fact| fact.e() != &id) {
        bail!("legacy Body {kind} {id:X} record contains another subject");
    }
    let expected = intrinsic_entity_id_v1(record_values(facts).into_iter().collect());
    if expected != id {
        bail!(
            "legacy Body {kind} {id:X} is not intrinsic under the historical v1 identity rule; expected {expected:X}"
        );
    }
    Ok(())
}

fn complete_record_witness(
    kind: &str,
    id: Id,
    record: &TribleSet,
    commits: &[&ProjectedLegacyCommit],
) -> Result<LegacyCommitCoordinate> {
    commits
        .iter()
        .filter(|commit| {
            record
                .iter()
                .all(|fact| commit.content.facts().contains(fact))
        })
        .map(|commit| commit.source)
        .min()
        .ok_or_else(|| {
            anyhow!(
                "legacy Body {kind} {id:X} is assembled across deltas without a complete authored record witness"
            )
        })
}

fn stage_unknown(
    reader: &PileReader,
    fragment: &mut Fragment,
    handle: Inline<Handle<UnknownBlob>>,
) -> Result<()> {
    let blob: Blob<UnknownBlob> = reader
        .get(handle)
        .with_context(|| format!("read attachment {}", hex::encode_upper(handle.raw)))?;
    let staged = fragment.blobs_mut().insert(blob);
    if staged.raw != handle.raw {
        bail!("staged Body attachment handle changed");
    }
    Ok(())
}

fn stage_capture_payloads(
    reader: &PileReader,
    fragment: &mut Fragment,
    row: &CaptureRow,
) -> Result<()> {
    if let Some(frame) = row.frame {
        stage_unknown(reader, fragment, frame.transmute())?;
    }
    if let Some(note) = row.note {
        stage_unknown(reader, fragment, note.transmute())?;
    }
    stage_unknown(reader, fragment, row.pose.transmute())
}

fn require_all_payloads_staged(content: &Fragment, catalog: &BodyCatalog) -> Result<()> {
    let mut blobs = content.blobs().clone();
    let local = blobs.reader().context("snapshot rewritten Body payloads")?;
    for row in catalog.captures.values() {
        if let Some(frame) = row.frame {
            if local.metadata(frame)?.is_none() {
                bail!(
                    "rewritten Body capture {:X} did not stage its frame",
                    row.id
                );
            }
        }
        for handle in [row.note, Some(row.pose)].into_iter().flatten() {
            if local.metadata(handle)?.is_none() {
                bail!("rewritten Body capture {:X} did not stage its text", row.id);
            }
        }
    }
    for row in catalog.intents.values() {
        if local.metadata(row.text)?.is_none() {
            bail!("rewritten Body intent {:X} did not stage its text", row.id);
        }
    }
    Ok(())
}

fn is_legacy_utterance_fact(fact: &Trible) -> bool {
    fact.a() == &legacy_utterance::text.id()
        || fact.a() == &legacy_utterance::channel.id()
        || (fact.a() == &metadata::tag.id()
            && (*fact.v::<inlineencodings::GenId>()).try_from_inline().ok()
                == Some(LEGACY_KIND_UTTERANCE))
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
                .map_err(|error| anyhow!("decode legacy Body short value: {error:?}"))
        })
        .collect()
}

fn exactly_one<T>(entity: Id, field: &str, mut values: Vec<T>) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "legacy Body entity {entity:X} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(values.pop().expect("length checked"))
}

fn validate_point(field: &str, interval: IntervalValue) -> Result<()> {
    let (start, end): (i128, i128) = interval
        .try_from_inline()
        .map_err(|error| anyhow!("decode {field}: {error:?}"))?;
    if start != end {
        bail!("{field} must be a point interval");
    }
    Ok(())
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    match (result, pile.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(anyhow!("close Body target pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Body target pile also failed: {close_error}"
        ))),
    }
}
#[cfg(test)]
mod tests {
    use std::fs::File;

    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;

    use super::*;
    use crate::collection_cutover::test_support::{TestBranchSpec, TestDeltaSpec, TestSourceSpec};
    use faculties::storage::{initialize_signer, load_signer, open_pile_strict};

    fn point(seconds: f64) -> IntervalValue {
        let epoch = Epoch::from_tai_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn force_v1(mut fragment: Fragment) -> (Id, Fragment) {
        let root = fragment.root().expect("one source record");
        let historical =
            intrinsic_entity_id_v1(record_values(fragment.facts()).into_iter().collect());
        let facts: TribleSet = fragment
            .facts()
            .iter()
            .map(|fact| Trible::force(&historical, fact.a(), fact.v::<inlineencodings::R256>()))
            .collect();
        let blobs = std::mem::take(fragment.blobs_mut());
        assert_ne!(root, historical);
        (historical, Fragment::from_facts_and_blobs(facts, blobs))
    }

    fn legacy_vision() -> (Id, Fragment) {
        let mut fragment = Fragment::empty();
        let frame = fragment.put::<blobencodings::RawBytes, _>(vec![1, 2, 3]);
        let pose = fragment.put::<blobencodings::UTF8String, _>("{}".to_owned());
        let note = fragment.put::<blobencodings::UTF8String, _>("kept".to_owned());
        fragment += body::capture_record(&CaptureRow {
            id: KIND_CAPTURE,
            created_at: point(1.0),
            frame: Some(frame),
            mime: Some("image/png".to_owned()),
            width: Some(640_u64.to_inline()),
            height: Some(480_u64.to_inline()),
            modality: "vision".to_owned(),
            note: Some(note),
            pose,
        });
        force_v1(fragment)
    }

    fn legacy_intent() -> (Id, Fragment) {
        let mut fragment = Fragment::empty();
        let text = fragment.put::<blobencodings::UTF8String, _>("lean in".to_owned());
        fragment += body::intent_record(&IntentRow {
            id: KIND_INTENT,
            created_at: point(2.0),
            text,
        });
        force_v1(fragment)
    }

    fn legacy_utterance() -> (Id, Fragment) {
        let mut fragment = Fragment::empty();
        let text = fragment.put::<blobencodings::UTF8String, _>("hello".to_owned());
        let audio = fragment.put::<blobencodings::RawBytes, _>(b"wav".to_vec());
        fragment += legacy_utterance_record(&LegacyBodyUtteranceRow {
            id: LEGACY_KIND_UTTERANCE,
            created_at: point(3.0),
            text,
            channel: "computer".to_owned(),
            audio,
            mime: "audio/wav".to_owned(),
        });
        force_v1(fragment)
    }

    #[test]
    fn plan_consumes_both_pins_rewrites_v1_and_excludes_voice() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("body.pile");
        File::create(&path).unwrap();
        let key = directory.path().join("body.key");
        initialize_signer(&path, Some(&key)).unwrap();

        let (old_capture, vision) = legacy_vision();
        let (old_intent, intent) = legacy_intent();
        let (_, utterance) = legacy_utterance();
        let signer = SigningKey::from_bytes(&[0x42; 32]);
        let frozen = TestSourceSpec::new(vec![
            TestBranchSpec::new(
                LEGACY_BODY_BRANCH_NAME,
                Id::new([0x42; 16]).unwrap(),
                signer.clone(),
                vec![
                    TestDeltaSpec::authored(
                        vision.clone() + intent + utterance,
                        "historical Body root",
                    ),
                    TestDeltaSpec::authored(Fragment::empty(), "historical Body empty"),
                ],
            ),
            TestBranchSpec::new(
                LEGACY_SENSES_BRANCH_NAME,
                Id::new([0x43; 16]).unwrap(),
                signer,
                vec![TestDeltaSpec::authored(
                    vision,
                    "historical Senses snapshot",
                )],
            ),
        ])
        .freeze(&path)
        .unwrap()
        .source;
        let plan = plan(&frozen).unwrap();
        assert_eq!(plan.source_pins().len(), 2);
        assert_eq!(plan.commits().len(), 3);
        assert_eq!(plan.report().legacy_captures, 1);
        assert_eq!(plan.report().canonical_captures, 1);
        assert_eq!(plan.report().legacy_intents, 1);
        assert_eq!(plan.report().canonical_intents, 1);
        assert_eq!(plan.report().excluded_utterances, 1);
        assert!(
            plan.commits()
                .iter()
                .filter(|commit| commit.fragment.facts().is_empty())
                .count()
                >= 1
        );

        let facts = plan.materialized_facts();
        let catalog = body::validate_catalog(frozen.reader(), &facts).unwrap();
        assert_eq!(catalog.captures.len(), 1);
        assert_eq!(catalog.intents.len(), 1);
        assert!(!facts.iter().any(|fact| fact.e() == &old_capture));
        assert!(!facts.iter().any(|fact| fact.e() == &old_intent));
        assert!(!facts.iter().any(is_legacy_utterance_fact));

        let published = publish(&frozen, &plan, &path, Some(&key)).unwrap();
        assert_eq!(published.len(), plan.commits().len());
        let signer = load_signer(&path, Some(&key)).unwrap();
        let pile = open_pile_strict(&path).unwrap();
        let mut collection =
            faculties::collection_names::open(pile, schema::DEFAULT_SCOPE_ID, signer);
        let materialized = collection.materialize().unwrap();
        assert_eq!(materialized, facts);
        let reader = collection.storage_mut().reader().unwrap();
        body::validate_catalog(&reader, &materialized).unwrap();
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn senses_only_utterance_cannot_be_stranded_between_body_and_voice() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("body.pile");
        File::create(&path).unwrap();
        let (_, utterance) = legacy_utterance();
        let signer = SigningKey::from_bytes(&[0x43; 32]);
        let frozen = TestSourceSpec::new(vec![
            TestBranchSpec::empty(
                LEGACY_BODY_BRANCH_NAME,
                Id::new([0x44; 16]).unwrap(),
                signer.clone(),
            ),
            TestBranchSpec::new(
                LEGACY_SENSES_BRANCH_NAME,
                Id::new([0x45; 16]).unwrap(),
                signer,
                vec![TestDeltaSpec::authored(
                    utterance,
                    "misplaced historical speech",
                )],
            ),
        ])
        .freeze(&path)
        .unwrap()
        .source;
        let error = plan(&frozen).unwrap_err();
        assert!(format!("{error:#}").contains("without a complete authored record witness"));
    }
}
