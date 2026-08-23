//! Stopped-world reconstruction of both historical Voice lineages.
//!
//! The Voice branch contains marker-free route and utterance records under the
//! first intrinsic identity epoch. Earlier utterances live on Body-specific
//! rows. Both exact pins are validated and mapped to the current live
//! transaction algebra: a source batch may split into several utterance
//! commits, while several historical route-entry commits may coalesce into one
//! complete route-generation commit.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::UnknownBlob;
use triblespace::core::blob::Blob;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::metadata as core_metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreMeta};
use triblespace::prelude::*;

use crate::body_cutover;
use crate::collection_cutover::{
    project_legacy_authored_commits, FrozenLegacyBranch, FrozenSource, LegacyCommitCoordinate,
    LegacyPinCoordinate, ProjectedLegacyCommit,
};
use faculties::schemas::body::LEGACY_BODY_BRANCH_NAME;
use faculties::schemas::voice::{self as schema, COLLECTION_SCOPE_ID, LEGACY_BRANCH_NAME};
use faculties::storage::{load_signer, open_pile_strict};
use faculties::voice;

const BODY_PRIVATE_CHANNEL: &str = "computer";
const BODY_PUBLIC_CHANNEL: &str = "body";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoiceMigrationCommit {
    /// Exact sorted legacy authored commits supporting this native
    /// transaction. Utterances and authored-empty Voice commits have singleton
    /// support; a reconstructed route generation may have several sources.
    pub sources: BTreeSet<LegacyCommitCoordinate>,
    pub fragment: Fragment,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VoiceMigrationReport {
    pub voice_authored_commits: usize,
    pub body_authored_commits: usize,
    pub native_commits: usize,
    pub split_authored_commits: usize,
    pub coalesced_native_commits: usize,
    pub body_without_voice_commits: usize,
    pub authored_empty_commits: usize,
    pub contentless_merges: usize,
    pub legacy_voice_routes: usize,
    pub canonical_routes: usize,
    pub legacy_voice_utterances: usize,
    pub legacy_body_utterances: usize,
    pub canonical_utterances: usize,
    pub output_facts: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoiceMigrationPlan {
    source_pins: [LegacyPinCoordinate; 2],
    authored_sources: BTreeSet<LegacyCommitCoordinate>,
    commits: Vec<VoiceMigrationCommit>,
    rewritten: TribleSet,
    report: VoiceMigrationReport,
}

impl VoiceMigrationPlan {
    pub const fn source_pins(&self) -> &[LegacyPinCoordinate; 2] {
        &self.source_pins
    }

    pub fn commits(&self) -> &[VoiceMigrationCommit] {
        &self.commits
    }

    pub const fn report(&self) -> &VoiceMigrationReport {
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
            bail!("planned Voice commit partition differs from its canonical rewrite");
        }

        let mut source_transactions = BTreeMap::<LegacyCommitCoordinate, usize>::new();
        for commit in &self.commits {
            if commit.sources.is_empty() {
                bail!("planned Voice transaction has no legacy source support");
            }
            for source in &commit.sources {
                *source_transactions.entry(*source).or_default() += 1;
            }
        }
        let mut publication_identities = BTreeMap::new();
        for commit in &self.commits {
            let data: Blob<SimpleArchive> = commit.fragment.facts().clone().to_blob();
            let metadata: Blob<SimpleArchive> = commit.fragment.metafacts().clone().to_blob();
            let identity = (data.get_handle().raw, metadata.get_handle().raw);
            if let Some(other_sources) = publication_identities.insert(identity, &commit.sources) {
                bail!(
                    "planned Voice transactions supported by {} and {} collapse to one durable CollectionCommit",
                    format_source_support(other_sources),
                    format_source_support(&commit.sources),
                );
            }
        }

        let mut authored_voice_sources = 0;
        let mut authored_body_sources = 0;
        for source in &self.authored_sources {
            let on_voice =
                source.branch == self.source_pins[0].id && source.pin == self.source_pins[0].value;
            let on_body =
                source.branch == self.source_pins[1].id && source.pin == self.source_pins[1].value;
            match (on_voice, on_body) {
                (true, false) => authored_voice_sources += 1,
                (false, true) => authored_body_sources += 1,
                _ => bail!("planned Voice source names an unknown or ambiguous pin"),
            }
        }
        let supported_sources: BTreeSet<_> = source_transactions.keys().copied().collect();
        if !supported_sources.is_subset(&self.authored_sources) {
            bail!("Voice transaction support names a non-authored source commit");
        }
        let omitted_sources: BTreeSet<_> = self
            .authored_sources
            .difference(&supported_sources)
            .copied()
            .collect();
        if omitted_sources.iter().any(|source| {
            source.branch != self.source_pins[1].id || source.pin != self.source_pins[1].value
        }) {
            bail!("Voice plan omits an authored source outside the Body projection");
        }

        let split_sources = source_transactions
            .values()
            .filter(|transactions| **transactions > 1)
            .count();
        let coalesced_commits = self
            .commits
            .iter()
            .filter(|commit| commit.sources.len() > 1)
            .count();

        if self.report.voice_authored_commits != authored_voice_sources
            || self.report.body_authored_commits != authored_body_sources
            || self.report.native_commits != self.commits.len()
            || self.report.split_authored_commits != split_sources
            || self.report.coalesced_native_commits != coalesced_commits
            || self.report.body_without_voice_commits != omitted_sources.len()
            || self.report.output_facts != self.rewritten.len()
            || self.report.legacy_voice_routes != self.report.canonical_routes
            || self.report.legacy_voice_utterances + self.report.legacy_body_utterances
                != self.report.canonical_utterances
        {
            bail!("Voice migration report disagrees with its planned commits");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PartitionedVoiceRewrite {
    content: Fragment,
    commits: Vec<VoiceMigrationCommit>,
    report: VoiceMigrationReport,
}

pub fn plan(source: &FrozenSource) -> Result<VoiceMigrationPlan> {
    let voice_branch = source
        .legacy_branch(LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Voice branch"))?;
    let body_branch = source
        .legacy_branch(LEGACY_BODY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Body branch"))?;

    let voice_authored =
        project_legacy_authored_commits(source, &voice_branch, voice::validate_known_payloads)
            .context("project frozen Voice authored commits")?;
    let body_authored = project_legacy_authored_commits(
        source,
        &body_branch,
        body_cutover::validate_legacy_body_payloads,
    )
    .context("project frozen Body commits for pre-extraction utterances")?;

    let rewritten = rewrite_voice_authored_commits(
        &voice_branch,
        &body_branch,
        &voice_authored,
        &body_authored,
        source.reader(),
    )
    .context("rewrite both historical Voice lineages")?;
    let plan = VoiceMigrationPlan {
        source_pins: [voice_branch.pin_coordinate(), body_branch.pin_coordinate()],
        authored_sources: voice_authored
            .iter()
            .chain(&body_authored)
            .map(|commit| commit.source)
            .collect(),
        commits: rewritten.commits,
        rewritten: rewritten.content.into_facts(),
        report: rewritten.report,
    };
    plan.verify_conservation()?;
    Ok(plan)
}

pub fn publish(
    source: &FrozenSource,
    plan: &VoiceMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    for pin in plan.source_pins {
        if !source.legacy_pins().contains(&pin) {
            bail!("Voice migration plan does not belong to this frozen source");
        }
    }
    plan.verify_conservation()?;

    crate::write_authority::publish(target, key)
        .context("initialize WRITE authority before Voice migration publication")?;

    let signer = load_signer(target, key)?;
    let pile = open_pile_strict(target)?;
    let mut collection = faculties::collection_names::open(pile, COLLECTION_SCOPE_ID, signer);
    let result = (|| {
        let mut candidate = collection
            .materialize()
            .context("materialize existing native Voice value")?;
        let mut staged = Fragment::empty();
        for commit in &plan.commits {
            validate_migration_fragment(&commit.fragment).with_context(|| {
                format!(
                    "validate Voice publication fragment supported by {}",
                    format_source_support(&commit.sources),
                )
            })?;
            candidate += commit.fragment.facts().clone();
            staged += commit.fragment.clone();
        }
        let reader = collection
            .storage_mut()
            .reader()
            .context("open Voice publication attachment reader")?;
        let overlay = staged
            .blobs_mut()
            .reader()
            .context("snapshot staged Voice migration attachments")?;
        voice::validate_catalog_with_overlay(&reader, &overlay, &candidate)
            .context("preflight complete post-migration Voice union")?;

        plan.commits
            .iter()
            .map(|commit| {
                collection.commit(commit.fragment.clone()).with_context(|| {
                    format!(
                        "publish Voice commit supported by {}",
                        format_source_support(&commit.sources),
                    )
                })
            })
            .collect()
    })();
    finish_pile(collection.into_storage(), result)
}

fn format_source_support(sources: &BTreeSet<LegacyCommitCoordinate>) -> String {
    sources
        .iter()
        .map(|source| hex::encode_upper(source.commit.raw))
        .collect::<Vec<_>>()
        .join(", ")
}

fn rewrite_voice_authored_commits(
    voice_branch: &FrozenLegacyBranch,
    body_branch: &FrozenLegacyBranch,
    voice_authored: &[ProjectedLegacyCommit],
    body_authored: &[ProjectedLegacyCommit],
    reader: &PileReader,
) -> Result<PartitionedVoiceRewrite> {
    validate_exact_authored_coverage(voice_branch, voice_authored, "Voice")?;
    validate_exact_authored_coverage(body_branch, body_authored, "Body")?;

    let mut legacy_voice = TribleSet::new();
    for commit in voice_authored {
        legacy_voice += commit.content.facts().clone();
    }
    let voice_catalog = voice::validate_legacy_catalog_v1(reader, &legacy_voice)
        .context("validate historical-v1 Voice catalog")?;
    let voice_entities = voice_catalog
        .routes
        .keys()
        .chain(voice_catalog.utterances.keys())
        .copied()
        .collect::<Vec<_>>();
    let voice_owners = unique_record_owners(voice_authored, voice_entities, "Voice record")?;

    let mut legacy_body = TribleSet::new();
    for commit in body_authored {
        legacy_body += commit.content.facts().clone();
    }
    let body_catalog = body_cutover::load_legacy_body_catalog(reader, &legacy_body)
        .context("validate historical Body catalog for Voice extraction")?;
    let body_owners = unique_record_owners(
        body_authored,
        body_catalog.utterances.keys().copied(),
        "Body utterance",
    )?;

    let mut authored_by_source = BTreeMap::new();
    for authored in voice_authored.iter().chain(body_authored) {
        if authored_by_source
            .insert(authored.source, authored)
            .is_some()
        {
            bail!("Voice rewrite repeats an authored source coordinate");
        }
    }

    let mut transactions = BTreeMap::<NativeTransactionKey, PendingNativeTransaction>::new();
    for row in voice_catalog.routes.values() {
        let record = voice::route_record(&row.channel, &row.device, row.priority, row.updated_at);
        add_native_record(
            &mut transactions,
            NativeTransactionKey::RouteGeneration {
                channel: row.channel.clone(),
                updated_at: row.updated_at.raw,
            },
            voice_owners[&row.id],
            record,
        )?;
    }
    for row in voice_catalog.utterances.values() {
        let mut record = voice::utterance_record(
            &row.channel,
            row.text,
            row.audio,
            row.mime.as_deref(),
            row.created_at,
        );
        let canonical = record
            .root()
            .expect("canonical Voice utterance has one root");
        stage_utterance_payloads(reader, &mut record, canonical, row.text, row.audio)?;
        add_native_record(
            &mut transactions,
            NativeTransactionKey::Utterance(canonical),
            voice_owners[&row.id],
            record,
        )?;
    }
    for row in body_catalog.utterances.values() {
        let channel = match row.channel.as_str() {
            BODY_PRIVATE_CHANNEL => schema::CHANNEL_SAY,
            BODY_PUBLIC_CHANNEL => schema::CHANNEL_SHOUT,
            _ => unreachable!("legacy Body channel validated"),
        };
        let mut record = voice::utterance_record(
            channel,
            row.text,
            Some(row.audio),
            Some(voice::AUDIO_WAV_MIME),
            row.created_at,
        );
        let canonical = record
            .root()
            .expect("canonical Body-derived Voice utterance has one root");
        stage_utterance_payloads(reader, &mut record, canonical, row.text, Some(row.audio))?;
        add_native_record(
            &mut transactions,
            NativeTransactionKey::Utterance(canonical),
            body_owners[&row.id],
            record,
        )?;
    }

    let mut contributing_sources: BTreeSet<_> = transactions
        .values()
        .flat_map(|transaction| transaction.sources.iter().copied())
        .collect();
    for authored in voice_authored {
        if !contributing_sources.contains(&authored.source) {
            if !authored.content.facts().is_empty() {
                bail!(
                    "authored Voice commit {} has content but supports no canonical Voice transaction",
                    hex::encode_upper(authored.source.commit.raw)
                );
            }
            let sources = BTreeSet::from([authored.source]);
            if transactions
                .insert(
                    NativeTransactionKey::EmptyVoice(authored.source),
                    PendingNativeTransaction {
                        sources,
                        fragment: Fragment::empty(),
                    },
                )
                .is_some()
            {
                bail!("Voice rewrite repeats an authored-empty source coordinate");
            }
            contributing_sources.insert(authored.source);
        }
    }
    let body_without_voice_commits = body_authored
        .iter()
        .map(|authored| authored.source)
        .filter(|source| !contributing_sources.contains(source))
        .count();

    let authored_empty_commits = voice_authored
        .iter()
        .chain(body_authored)
        .filter(|commit| commit.content.facts().is_empty())
        .count();
    let native_commits = transactions.len();
    let coalesced_native_commits = transactions
        .values()
        .filter(|transaction| transaction.sources.len() > 1)
        .count();
    let mut supported_transactions = BTreeMap::<LegacyCommitCoordinate, usize>::new();
    for transaction in transactions.values() {
        for source in &transaction.sources {
            *supported_transactions.entry(*source).or_default() += 1;
        }
    }
    let split_authored_commits = supported_transactions
        .values()
        .filter(|count| **count > 1)
        .count();

    let mut content = Fragment::empty();
    let mut seen = TribleSet::new();
    let mut commits = Vec::with_capacity(native_commits);
    for (key, transaction) in transactions {
        let overlap = seen.intersect(transaction.fragment.facts());
        if !overlap.is_empty() {
            bail!(
                "canonical Voice transactions overlap by {} fact(s); two legacy records collapse",
                overlap.len()
            );
        }
        validate_migration_fragment(&transaction.fragment).with_context(|| {
            format!(
                "canonical Voice transaction supported by {} violates the native transaction boundary",
                format_source_support(&transaction.sources)
            )
        })?;
        seen += transaction.fragment.facts().clone();
        content += transaction.fragment.clone();

        let mut fragment = transaction.fragment;
        for source in &transaction.sources {
            fragment.describe_with(authored_by_source[source].metadata.clone());
        }
        match key {
            NativeTransactionKey::EmptyVoice(source) => {
                if !fragment.facts().is_empty()
                    || transaction.sources.len() != 1
                    || !transaction.sources.contains(&source)
                {
                    bail!("authored-empty Voice transaction has inconsistent source support");
                }
                // Parentage distinguishes legacy authored-empty commits but
                // does not appear in their projected user metadata. Retain the
                // exact source coordinate so equal empty inputs cannot collapse
                // into one content-addressed CollectionCommit.
                fragment.describe_with(empty_voice_source_provenance(source));
            }
            NativeTransactionKey::RouteGeneration { .. } | NativeTransactionKey::Utterance(_) => {
                if fragment.facts().is_empty() {
                    bail!("non-empty Voice transaction key produced an empty fragment");
                }
            }
        }
        commits.push(VoiceMigrationCommit {
            sources: transaction.sources,
            fragment,
        });
    }
    if seen != *content.facts() {
        bail!("canonical Voice transaction partition does not equal the global rewrite");
    }
    if voice::active_facts(content.facts()) != *content.facts() {
        bail!("canonical Voice rewrite contains marker-free facts");
    }

    let canonical = voice::validate_catalog(reader, content.facts())
        .context("validate canonical live Voice rewrite")?;
    let expected_utterances = voice_catalog.utterances.len() + body_catalog.utterances.len();
    if canonical.routes.len() != voice_catalog.routes.len()
        || canonical.utterances.len() != expected_utterances
    {
        bail!("Voice route or utterance conservation failed");
    }
    require_output_payloads_staged(&content, &canonical)?;

    let report = VoiceMigrationReport {
        voice_authored_commits: voice_authored.len(),
        body_authored_commits: body_authored.len(),
        native_commits,
        split_authored_commits,
        coalesced_native_commits,
        body_without_voice_commits,
        authored_empty_commits,
        contentless_merges: [voice_branch, body_branch]
            .into_iter()
            .flat_map(|branch| branch.deltas.iter())
            .filter(|delta| !delta.is_authored())
            .count(),
        legacy_voice_routes: voice_catalog.routes.len(),
        canonical_routes: canonical.routes.len(),
        legacy_voice_utterances: voice_catalog.utterances.len(),
        legacy_body_utterances: body_catalog.utterances.len(),
        canonical_utterances: canonical.utterances.len(),
        output_facts: content.facts().len(),
    };
    Ok(PartitionedVoiceRewrite {
        content,
        commits,
        report,
    })
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
enum NativeTransactionKey {
    RouteGeneration {
        channel: String,
        updated_at: [u8; 32],
    },
    Utterance(Id),
    EmptyVoice(LegacyCommitCoordinate),
}

struct PendingNativeTransaction {
    sources: BTreeSet<LegacyCommitCoordinate>,
    fragment: Fragment,
}

fn empty_voice_source_provenance(source: LegacyCommitCoordinate) -> Fragment {
    entity! {
        core_metadata::description: format!(
            "Voice legacy authored-empty source branch {:X}, pin {}, commit {}",
            source.branch,
            hex::encode_upper(source.pin.raw),
            hex::encode_upper(source.commit.raw),
        )
    }
}

fn add_native_record(
    transactions: &mut BTreeMap<NativeTransactionKey, PendingNativeTransaction>,
    key: NativeTransactionKey,
    source: LegacyCommitCoordinate,
    record: Fragment,
) -> Result<()> {
    let transaction = transactions
        .entry(key)
        .or_insert_with(|| PendingNativeTransaction {
            sources: BTreeSet::new(),
            fragment: Fragment::empty(),
        });
    let overlap = transaction.fragment.facts().intersect(record.facts());
    if !overlap.is_empty() {
        bail!(
            "canonical Voice records overlap by {} fact(s); historical records collapse",
            overlap.len()
        );
    }
    transaction.sources.insert(source);
    transaction.fragment += record;
    Ok(())
}

fn stage_utterance_payloads(
    reader: &PileReader,
    fragment: &mut Fragment,
    utterance: Id,
    text: voice::TextHandle,
    audio: Option<voice::AudioHandle>,
) -> Result<()> {
    stage_payload(reader, fragment, text.transmute(), utterance, "text")?;
    if let Some(audio) = audio {
        stage_payload(reader, fragment, audio.transmute(), utterance, "audio")?;
    }
    Ok(())
}

fn stage_payload(
    reader: &PileReader,
    fragment: &mut Fragment,
    handle: Inline<Handle<UnknownBlob>>,
    utterance: Id,
    field: &str,
) -> Result<()> {
    let blob: Blob<UnknownBlob> = reader.get(handle).with_context(|| {
        format!(
            "read canonical Voice utterance {utterance:X} {field} payload {}",
            hex::encode_upper(handle.raw)
        )
    })?;
    let staged = fragment.blobs_mut().insert(blob);
    if staged != handle {
        bail!("staged Voice utterance {utterance:X} {field} payload changed identity");
    }
    Ok(())
}

/// Every non-empty migration fragment obeys the live writer's native
/// transaction boundary. A genuinely authored-empty Voice delta remains an
/// empty Voice transaction; Body deltas outside the speech projection are
/// accounted as omitted and never manufacture empty Voice authority.
fn validate_migration_fragment(fragment: &Fragment) -> Result<()> {
    if fragment.facts().is_empty() {
        return Ok(());
    }
    if voice::active_facts(fragment.facts()) != *fragment.facts() {
        bail!("Voice migration output contains marker-free historical facts");
    }
    voice::validate_commit_fragment(fragment.facts())?;
    Ok(())
}

fn validate_exact_authored_coverage(
    branch: &FrozenLegacyBranch,
    authored: &[ProjectedLegacyCommit],
    label: &str,
) -> Result<()> {
    let expected: BTreeSet<_> = branch
        .deltas
        .iter()
        .filter(|delta| delta.is_authored())
        .map(|delta| LegacyCommitCoordinate {
            branch: branch.branch,
            pin: branch.pin,
            commit: delta.commit,
        })
        .collect();
    let actual: BTreeSet<_> = authored.iter().map(|commit| commit.source).collect();
    if actual.len() != authored.len() || actual != expected {
        bail!(
            "{label} authored commits do not exactly cover frozen branch {:X}",
            branch.branch
        );
    }
    Ok(())
}

fn unique_record_owners(
    authored: &[ProjectedLegacyCommit],
    entities: impl IntoIterator<Item = Id>,
    kind: &str,
) -> Result<BTreeMap<Id, LegacyCommitCoordinate>> {
    let mut owners = BTreeMap::new();
    for entity in entities {
        let witnesses: BTreeSet<_> = authored
            .iter()
            .filter(|commit| {
                commit
                    .content
                    .facts()
                    .iter()
                    .any(|fact| fact.e() == &entity)
            })
            .map(|commit| commit.source)
            .collect();
        if witnesses.len() != 1 {
            bail!(
                "legacy {kind} {entity:X} spans {} authored commits; expected one atomic record",
                witnesses.len()
            );
        }
        owners.insert(entity, *witnesses.iter().next().expect("one witness"));
    }
    Ok(owners)
}

fn require_output_payloads_staged(content: &Fragment, catalog: &voice::VoiceCatalog) -> Result<()> {
    let mut blobs = content.blobs().clone();
    let local = blobs
        .reader()
        .context("snapshot rewritten Voice payloads")?;
    for row in catalog.utterances.values() {
        if local.metadata(row.text)?.is_none() {
            bail!(
                "rewritten Voice utterance {:X} did not stage its text",
                row.id
            );
        }
        if let Some(audio) = row.audio {
            if local.metadata(audio)?.is_none() {
                bail!(
                    "rewritten Voice utterance {:X} did not stage its audio",
                    row.id
                );
            }
        }
    }
    Ok(())
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    match (result, pile.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(anyhow!("close Voice target pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Voice target pile also failed: {close_error}"
        ))),
    }
}
#[cfg(test)]
mod tests {
    use std::fs::File;

    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use triblespace::core::metadata;
    use triblespace::core::trible::intrinsic_entity_id_v1;

    use super::*;
    use crate::body_cutover::{legacy_utterance, LEGACY_KIND_UTTERANCE};
    use crate::collection_cutover::test_support::{TestBranchSpec, TestDeltaSpec, TestSourceSpec};
    use faculties::body::{self, IntentRow};
    use faculties::schemas::body::{capture, KIND_INTENT};
    use faculties::schemas::voice::{
        route, utterance, CHANNEL_SAY, CHANNEL_SHOUT, KIND_ROUTE, KIND_UTTERANCE,
    };
    use faculties::storage::{initialize_signer, load_signer, open_pile_strict};

    fn point(seconds: f64) -> voice::IntervalValue {
        let epoch = Epoch::from_tai_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn force_v1(mut fragment: Fragment) -> (Id, Fragment) {
        let current = fragment.root().expect("one historical record");
        let pairs: BTreeSet<(Id, [u8; 32])> = fragment
            .facts()
            .iter()
            .map(|fact| (*fact.a(), fact.v::<inlineencodings::R256>().raw))
            .collect();
        let historical = intrinsic_entity_id_v1(pairs.into_iter().collect());
        let facts: TribleSet = fragment
            .facts()
            .iter()
            .map(|fact| Trible::force(&historical, fact.a(), fact.v::<inlineencodings::R256>()))
            .collect();
        let blobs = std::mem::take(fragment.blobs_mut());
        assert_ne!(current, historical);
        (historical, Fragment::from_facts_and_blobs(facts, blobs))
    }

    fn legacy_route_entry(device: &str, priority: u64, updated_at: f64) -> (Id, Fragment) {
        force_v1(entity! {
            metadata::tag: &KIND_ROUTE,
            metadata::updated_at: point(updated_at),
            route::channel: CHANNEL_SAY,
            route::device: device,
            route::priority: priority.to_inline(),
        })
    }

    fn legacy_route() -> (Id, Fragment) {
        legacy_route_entry("AirPods", 0, 1.0)
    }

    fn legacy_voice_utterance() -> (Id, Fragment) {
        let mut fragment = Fragment::empty();
        let text = fragment.put::<blobencodings::UTF8String, _>("voice words".to_owned());
        let audio = fragment.put::<blobencodings::RawBytes, _>(b"voice wav".to_vec());
        fragment += entity! {
            metadata::tag: &KIND_UTTERANCE,
            metadata::created_at: point(2.0),
            utterance::channel: CHANNEL_SHOUT,
            utterance::text: text,
            utterance::audio: audio,
            utterance::mime: voice::AUDIO_WAV_MIME,
        };
        force_v1(fragment)
    }

    fn legacy_body_utterance_at(text_value: &str, audio_value: &[u8], at: f64) -> (Id, Fragment) {
        let mut fragment = Fragment::empty();
        let text = fragment.put::<blobencodings::UTF8String, _>(text_value.to_owned());
        let audio = fragment.put::<blobencodings::RawBytes, _>(audio_value.to_vec());
        fragment += entity! {
            metadata::tag: &LEGACY_KIND_UTTERANCE,
            metadata::created_at: point(at),
            legacy_utterance::channel: BODY_PRIVATE_CHANNEL,
            legacy_utterance::text: text,
            capture::frame: audio,
            capture::mime: voice::AUDIO_WAV_MIME,
        };
        force_v1(fragment)
    }

    fn legacy_body_utterance() -> (Id, Fragment) {
        legacy_body_utterance_at("body words", b"body wav", 3.0)
    }

    fn legacy_body_intent_at(text_value: &str, at: f64) -> (Id, Fragment) {
        let mut fragment = Fragment::empty();
        let text = fragment.put::<blobencodings::UTF8String, _>(text_value.to_owned());
        fragment += body::intent_record(&IntentRow {
            id: KIND_INTENT,
            created_at: point(at),
            text,
        });
        force_v1(fragment)
    }

    fn legacy_body_intent() -> (Id, Fragment) {
        legacy_body_intent_at("move gently", 4.0)
    }

    #[test]
    fn plan_reconstructs_voice_and_body_lineages_as_live_records() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("voice.pile");
        File::create(&path).unwrap();
        let key = directory.path().join("voice.key");
        initialize_signer(&path, Some(&key)).unwrap();

        let (old_route, route_record) = legacy_route();
        let (old_voice, utterance_record) = legacy_voice_utterance();
        let (old_body, body_utterance) = legacy_body_utterance();
        let (_, body_intent) = legacy_body_intent();

        let signer = SigningKey::from_bytes(&[0x61; 32]);
        let frozen = TestSourceSpec::new(vec![
            TestBranchSpec::new(
                LEGACY_BRANCH_NAME,
                Id::new([0x61; 16]).unwrap(),
                signer.clone(),
                vec![
                    TestDeltaSpec::authored(route_record, "historical Voice route"),
                    TestDeltaSpec::authored(utterance_record, "historical Voice utterance"),
                    TestDeltaSpec::authored(Fragment::empty(), "historical Voice empty"),
                ],
            ),
            TestBranchSpec::new(
                LEGACY_BODY_BRANCH_NAME,
                Id::new([0x62; 16]).unwrap(),
                signer,
                vec![TestDeltaSpec::authored(
                    body_utterance + body_intent,
                    "historical Body speech and intent",
                )],
            ),
        ])
        .freeze(&path)
        .unwrap()
        .source;
        let plan = plan(&frozen).unwrap();
        assert_eq!(plan.source_pins().len(), 2);
        assert_eq!(plan.commits().len(), 4);
        assert_eq!(plan.report().native_commits, 4);
        assert_eq!(plan.report().split_authored_commits, 0);
        assert_eq!(plan.report().coalesced_native_commits, 0);
        assert_eq!(plan.report().body_without_voice_commits, 0);
        assert_eq!(plan.report().legacy_voice_routes, 1);
        assert_eq!(plan.report().canonical_routes, 1);
        assert_eq!(plan.report().legacy_voice_utterances, 1);
        assert_eq!(plan.report().legacy_body_utterances, 1);
        assert_eq!(plan.report().canonical_utterances, 2);
        assert!(plan
            .commits()
            .iter()
            .all(|commit| commit.sources.len() == 1));
        assert_eq!(
            plan.commits()
                .iter()
                .filter(|commit| commit.fragment.facts().is_empty())
                .count(),
            1
        );

        let facts = plan.materialized_facts();
        assert_eq!(voice::active_facts(&facts), facts);
        let catalog = voice::validate_catalog(frozen.reader(), &facts).unwrap();
        assert_eq!(catalog.routes.len(), 1);
        assert_eq!(catalog.utterances.len(), 2);
        assert!(catalog
            .utterances
            .values()
            .any(|row| row.channel == CHANNEL_SAY));
        assert!(catalog
            .utterances
            .values()
            .any(|row| row.channel == CHANNEL_SHOUT));
        assert!(!facts
            .iter()
            .any(|fact| [old_route, old_voice, old_body].contains(fact.e())));

        let published = publish(&frozen, &plan, &path, Some(&key)).unwrap();
        assert_eq!(published.len(), plan.commits().len());
        let signer = load_signer(&path, Some(&key)).unwrap();
        let pile = open_pile_strict(&path).unwrap();
        let mut collection = faculties::collection_names::open(pile, COLLECTION_SCOPE_ID, signer);
        let materialized = collection.materialize().unwrap();
        assert_eq!(materialized, facts);
        let reader = collection.storage_mut().reader().unwrap();
        voice::validate_catalog(&reader, &materialized).unwrap();
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn identical_authored_empty_sources_publish_as_distinct_idempotent_commits() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("empty-source.pile");
        let target_path = directory.path().join("empty-target.pile");
        let key = directory.path().join("empty-target.key");
        File::create(&source_path).unwrap();
        File::create(&target_path).unwrap();

        initialize_signer(&target_path, Some(&key)).unwrap();
        crate::write_authority::publish(&target_path, Some(&key)).unwrap();
        let signer = SigningKey::from_bytes(&[0x64; 32]);
        let fixture = TestSourceSpec::new(vec![
            TestBranchSpec::new(
                LEGACY_BRANCH_NAME,
                Id::new([0x64; 16]).unwrap(),
                signer.clone(),
                vec![
                    TestDeltaSpec::authored(
                        Fragment::empty(),
                        "identical authored-empty Voice metadata",
                    ),
                    TestDeltaSpec::authored(
                        Fragment::empty(),
                        "identical authored-empty Voice metadata",
                    ),
                ],
            ),
            TestBranchSpec::empty(
                LEGACY_BODY_BRANCH_NAME,
                Id::new([0x65; 16]).unwrap(),
                signer,
            ),
        ])
        .freeze(&source_path)
        .unwrap();
        let frozen = &fixture.source;
        let branch = fixture.branch(LEGACY_BRANCH_NAME);
        let projected =
            project_legacy_authored_commits(&frozen, &branch, voice::validate_known_payloads)
                .unwrap();
        assert_eq!(projected.len(), 2);
        assert_ne!(projected[0].source, projected[1].source);

        let plan = plan(&frozen).unwrap();
        assert_eq!(plan.report().voice_authored_commits, 2);
        assert_eq!(plan.report().body_authored_commits, 0);
        assert_eq!(plan.report().native_commits, 2);
        assert_eq!(plan.report().authored_empty_commits, 2);
        assert_eq!(plan.report().split_authored_commits, 0);
        assert_eq!(plan.report().coalesced_native_commits, 0);
        assert_eq!(plan.report().body_without_voice_commits, 0);
        assert_eq!(plan.report().output_facts, 0);
        assert!(plan.materialized_facts().is_empty());
        assert!(plan.commits().iter().all(|commit| {
            commit.sources.len() == 1
                && commit.fragment.facts().is_empty()
                && !commit.fragment.metafacts().is_empty()
        }));
        let sources: Vec<_> = plan
            .commits()
            .iter()
            .map(|commit| *commit.sources.iter().next().unwrap())
            .collect();
        assert_eq!(
            sources.iter().copied().collect::<BTreeSet<_>>(),
            projected
                .iter()
                .map(|commit| commit.source)
                .collect::<BTreeSet<_>>()
        );
        for (commit, source) in plan.commits().iter().zip(&sources) {
            let provenance = empty_voice_source_provenance(*source);
            assert!(provenance
                .facts()
                .iter()
                .all(|fact| commit.fragment.metafacts().contains(fact)));
        }
        let mut all_planned_metadata = Fragment::empty();
        for commit in plan.commits() {
            all_planned_metadata += Fragment::from_facts_and_blobs(
                commit.fragment.metafacts().clone(),
                commit.fragment.blobs().clone(),
            );
        }
        let mut colliding = plan.clone();
        for commit in &mut colliding.commits {
            let mut fragment = Fragment::empty();
            fragment.describe_with(all_planned_metadata.clone());
            commit.fragment = fragment;
        }
        let error = colliding.verify_conservation().unwrap_err();
        assert!(format!("{error:#}").contains("collapse to one durable CollectionCommit"));

        // Repository commit timestamps are intentionally sampled per commit,
        // so construct the exact equal-user-metadata collision deterministically
        // at the native boundary. Only source-coordinate provenance differs.
        let identical_user_metadata =
            entity! { metadata::description: "identical authored-empty Voice metadata" };
        let fragments: Vec<_> = sources
            .iter()
            .map(|source| {
                let mut fragment = Fragment::empty();
                fragment.describe_with(identical_user_metadata.clone());
                fragment.describe_with(empty_voice_source_provenance(*source));
                fragment
            })
            .collect();
        assert_eq!(fragments.len(), 2);
        assert!(fragments.iter().all(|fragment| identical_user_metadata
            .facts()
            .iter()
            .all(|fact| fragment.metafacts().contains(fact))));

        let signer = load_signer(&target_path, Some(&key)).unwrap();
        let pile = open_pile_strict(&target_path).unwrap();
        let mut collection = faculties::collection_names::open(pile, COLLECTION_SCOPE_ID, signer);
        let first: Vec<_> = fragments
            .iter()
            .map(|fragment| collection.commit(fragment.clone()).unwrap())
            .collect();
        collection.into_storage().close().unwrap();
        assert_eq!(first.len(), 2);
        assert_ne!(first[0], first[1]);
        let length = std::fs::metadata(&target_path).unwrap().len();

        let signer = load_signer(&target_path, Some(&key)).unwrap();
        let pile = open_pile_strict(&target_path).unwrap();
        let mut collection = faculties::collection_names::open(pile, COLLECTION_SCOPE_ID, signer);
        let replay: Vec<_> = fragments
            .iter()
            .map(|fragment| collection.commit(fragment.clone()).unwrap())
            .collect();
        collection.into_storage().close().unwrap();
        assert_eq!(replay, first);
        assert_eq!(std::fs::metadata(&target_path).unwrap().len(), length);

        let signer = load_signer(&target_path, Some(&key)).unwrap();
        let pile = open_pile_strict(&target_path).unwrap();
        let mut collection = faculties::collection_names::open(pile, COLLECTION_SCOPE_ID, signer);
        let snapshot = collection.snapshot().unwrap();
        assert!(snapshot.facts().is_empty());
        assert_eq!(snapshot.commits().len(), 2);
        assert_eq!(
            snapshot
                .commits()
                .iter()
                .map(CollectionCommit::id)
                .collect::<BTreeSet<_>>(),
            first.iter().map(CollectionCommit::id).collect()
        );
        drop(snapshot);
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn squashed_body_batch_splits_into_nine_utterance_transactions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("squashed-body.pile");
        File::create(&path).unwrap();

        let mut squash = Fragment::empty();
        for index in 0..9 {
            let text = format!("body words {index}");
            let audio = format!("body wav {index}");
            squash += legacy_body_utterance_at(&text, audio.as_bytes(), 10.0 + index as f64).1;
        }
        squash += legacy_body_intent_at("intent inside squash", 30.0).1;
        let signer = SigningKey::from_bytes(&[0x62; 32]);
        let fixture = TestSourceSpec::new(vec![
            TestBranchSpec::empty(
                LEGACY_BRANCH_NAME,
                Id::new([0x66; 16]).unwrap(),
                signer.clone(),
            ),
            TestBranchSpec::new(
                LEGACY_BODY_BRANCH_NAME,
                Id::new([0x67; 16]).unwrap(),
                signer,
                vec![
                    TestDeltaSpec::authored(squash, "squashed body"),
                    TestDeltaSpec::authored(
                        legacy_body_intent_at("later non-voice body work", 31.0).1,
                        "body only",
                    ),
                ],
            ),
        ])
        .freeze(&path)
        .unwrap();
        let frozen = &fixture.source;
        let body = fixture.branch(LEGACY_BODY_BRANCH_NAME);
        let projected_body = project_legacy_authored_commits(
            &frozen,
            &body,
            body_cutover::validate_legacy_body_payloads,
        )
        .unwrap();
        let plan = plan(&frozen).unwrap();

        assert_eq!(plan.report().voice_authored_commits, 0);
        assert_eq!(plan.report().body_authored_commits, 2);
        assert_eq!(plan.report().native_commits, 9);
        assert_eq!(plan.report().split_authored_commits, 1);
        assert_eq!(plan.report().coalesced_native_commits, 0);
        assert_eq!(plan.report().body_without_voice_commits, 1);
        assert_eq!(plan.report().legacy_body_utterances, 9);
        assert_eq!(plan.report().canonical_utterances, 9);

        let support = plan.commits()[0].sources.clone();
        assert_eq!(support.len(), 1);
        assert!(plan
            .commits()
            .iter()
            .all(|commit| commit.sources == support));
        let source = *support.iter().next().unwrap();
        let source_metadata = &projected_body
            .iter()
            .find(|commit| commit.source == source)
            .unwrap()
            .metadata;

        let facts = plan.materialized_facts();
        let catalog = voice::validate_catalog(frozen.reader(), &facts).unwrap();
        for commit in plan.commits() {
            voice::validate_commit_fragment(commit.fragment.facts()).unwrap();
            let transaction = voice::load_catalog(commit.fragment.facts()).unwrap();
            assert!(transaction.routes.is_empty());
            assert_eq!(transaction.utterances.len(), 1);
            assert!(source_metadata
                .facts()
                .iter()
                .all(|fact| commit.fragment.metafacts().contains(fact)));

            let own = *transaction.utterances.keys().next().unwrap();
            let mut blobs = commit.fragment.blobs().clone();
            let local = blobs.reader().unwrap();
            for row in catalog.utterances.values() {
                assert_eq!(local.metadata(row.text).unwrap().is_some(), row.id == own);
                assert_eq!(
                    local.metadata(row.audio.unwrap()).unwrap().is_some(),
                    row.id == own
                );
            }
        }
    }

    #[test]
    fn historical_route_entries_coalesce_into_one_complete_generation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("route-generation.pile");
        File::create(&path).unwrap();
        let routes = ["AirPods Max", "AirPods Pro", "Headphones"]
            .into_iter()
            .enumerate()
            .map(|(priority, device)| {
                TestDeltaSpec::authored(
                    legacy_route_entry(device, priority as u64, 40.0).1,
                    format!("route entry {priority}"),
                )
            })
            .collect();
        let signer = SigningKey::from_bytes(&[0x63; 32]);
        let fixture = TestSourceSpec::new(vec![
            TestBranchSpec::new(
                LEGACY_BRANCH_NAME,
                Id::new([0x68; 16]).unwrap(),
                signer.clone(),
                routes,
            ),
            TestBranchSpec::empty(
                LEGACY_BODY_BRANCH_NAME,
                Id::new([0x69; 16]).unwrap(),
                signer,
            ),
        ])
        .freeze(&path)
        .unwrap();
        let frozen = &fixture.source;
        let voice_branch = fixture.branch(LEGACY_BRANCH_NAME);
        let projected_voice =
            project_legacy_authored_commits(&frozen, &voice_branch, voice::validate_known_payloads)
                .unwrap();
        let plan = plan(&frozen).unwrap();

        assert_eq!(plan.report().voice_authored_commits, 3);
        assert_eq!(plan.report().native_commits, 1);
        assert_eq!(plan.report().split_authored_commits, 0);
        assert_eq!(plan.report().coalesced_native_commits, 1);
        assert_eq!(plan.report().canonical_routes, 3);
        let commit = &plan.commits()[0];
        assert_eq!(
            commit.sources,
            projected_voice.iter().map(|source| source.source).collect()
        );
        voice::validate_commit_fragment(commit.fragment.facts()).unwrap();
        assert_eq!(
            voice::load_catalog(commit.fragment.facts())
                .unwrap()
                .routes
                .len(),
            3
        );
        assert!(projected_voice.iter().all(|source| source
            .metadata
            .facts()
            .iter()
            .all(|fact| commit.fragment.metafacts().contains(fact))));
    }

    #[test]
    fn nonempty_migration_partitions_obey_live_voice_boundaries() {
        let first_text = Inline::<inlineencodings::Handle<blobencodings::UTF8String>>::new([1; 32]);
        let second_text =
            Inline::<inlineencodings::Handle<blobencodings::UTF8String>>::new([2; 32]);
        let first = voice::utterance_record(CHANNEL_SAY, first_text, None, None, point(5.0));
        let second = voice::utterance_record(CHANNEL_SHOUT, second_text, None, None, point(6.0));

        validate_migration_fragment(&first).unwrap();
        let error = validate_migration_fragment(&(first + second)).unwrap_err();
        assert!(format!("{error:#}").contains("one utterance or one route generation"));
        validate_migration_fragment(&Fragment::empty()).unwrap();
    }
}
