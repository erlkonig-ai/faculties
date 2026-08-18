//! Stopped-world additive projection of the legacy Message repository DAG.
//!
//! Historical Message records were accumulated as independent tribles.  A
//! message or read occurrence can therefore become complete only after facts
//! from several authored ancestors meet, and the old random read ids do not
//! encode their semantic `(message, reader)` identity. Every authored legacy
//! fragment remains byte-for-byte present in its corresponding native commit;
//! canonical intrinsic envelopes and read markers are additive shadows.
//! Repository ancestry remains the only historical authority: the migration
//! adds a canonical record at every authored frontier where the complete
//! legacy occurrence first exists. A contentless merge may carry availability
//! forward, but may never create a new signed assertion by combining
//! incomplete parents.
//!
//! Legacy group messages did not freeze their audience. The migration uses
//! the exact same deterministic Relations replay as `relations_cutover` and
//! selects the unique ancestry-maximal authored snapshot covering every
//! eligible historical reader. It never synthesizes membership. Targetless
//! and non-inbox read observations are omitted only through a source-commit
//! and complete-shape audit. Source timestamps are preserved as observations
//! and never choose a branch, a recipient, or an authority.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::attribute::Attribute;
use triblespace::core::blob::encodings::longstring::LongString;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::id::{ExclusiveId, Id};
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::encodings::shortstring::ShortString;
use triblespace::core::inline::{Inline, InlineEncoding, RawInline};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStoreGet, CommitHandle};
use triblespace::core::trible::{Fragment, TribleSet, V_START};
use triblespace::macros::{attributes, entity, id_hex};
use triblespace::prelude::inlineencodings;

use crate::collection_cutover::{
    project_legacy_authored_commits, publish_fragments, FrozenLegacyBranch, FrozenSource,
    LegacyCommitCoordinate, LegacyPinCoordinate, ProjectedLegacyCommit,
};
use crate::message as current;
use crate::relations;
use crate::relations_cutover;
use crate::schemas::message::{
    self as schema, local, GROUP_SNAPSHOT_BASIS_CUTOVER_RECONSTRUCTED, KIND_MESSAGE_ID,
    KIND_READ_ID,
};
use crate::schemas::relations::KIND_GROUP_SNAPSHOT;

pub use crate::schemas::message::LEGACY_BRANCH_NAME;

const KIND_PARTY_ID: Id = id_hex!("3AA2883528D3812067DFA1CD5DE5F8B8");
const PARTY_LOCAL_AGENT_ID: Id = id_hex!("5EBC44A9FC4C8444AA01DFA7AC315AD5");
const PARTY_USER_ID: Id = id_hex!("7A39EB8857D1912501DACDA4DB29077B");
/// The early two-party Message schema used an anonymous `user` anchor.
/// Relations later introduced the explicit stable person anchor while keeping
/// the local-agent anchor. The cutover settles that one historical alias
/// instead of fabricating a second person absent from Relations.
const PARTY_USER_SUCCESSOR_ID: Id = id_hex!("3A0C3F18C8F8340058A5C68DEA857939");

const LEGACY_CREATED_AT_LE: Id = id_hex!("53ECCC7489AF8D30EF385ED12073F4A3");
const LEGACY_CREATED_AT_ORDERED: Id = id_hex!("5FA453867880877B613B7632A233419B");
const LEGACY_READ_AT_LE: Id = id_hex!("934C5AD3DA8F7A2EB467460E50D17A4F");

/// Audited acknowledgements from the historical squashed import whose named
/// messages are absent from the complete captured branch.  They cannot form a
/// canonical read fact without inventing an envelope.  Keeping the exact
/// occurrence/target pairs here makes their omission narrow and fail-closed:
/// a newly orphaned read is corruption, not another item silently discarded.
const KNOWN_ORPHAN_READS: [(Id, Id); 11] = [
    (
        id_hex!("9025D950CF87A36065D53089294DE130"),
        id_hex!("CCC6C59F3F1657FD0A25BA7B1E1F13B8"),
    ),
    (
        id_hex!("9025DA91E823A4A7BCED1869DFFB3684"),
        id_hex!("28364F1C9D529EFEDF14930EBCC7CC89"),
    ),
    (
        id_hex!("9025DBEB0379078DFE2AC1E860D6CE02"),
        id_hex!("7F928778C7553E7A350E8F1DB18DAB78"),
    ),
    (
        id_hex!("9025DE60B2FB0C47ADEF0316C33AF276"),
        id_hex!("400BE57899C55D58AD65529B1E253041"),
    ),
    (
        id_hex!("9025DF91CB13051FCD1E6A20B01145F4"),
        id_hex!("2F378CC2BB2ADF788653870192E9F889"),
    ),
    (
        id_hex!("9025E0E8FCCD44D8D35CA1E11CB25DA7"),
        id_hex!("F716D7EEF834B121A16B45EBD170AF1C"),
    ),
    (
        id_hex!("9025E35EDD771A9ED09C9196C888B9CE"),
        id_hex!("74114E95B55F203F4234F53B4BE1EE58"),
    ),
    (
        id_hex!("902634B9ADDF3523150E7D1F742D2B82"),
        id_hex!("54AE091D380AD80DB9B9FB1D1B0E9FED"),
    ),
    (
        id_hex!("902637343CD2FB62503D65654924259F"),
        id_hex!("ABBE961349D723206695BE8D2CB98C1E"),
    ),
    (
        id_hex!("B2073ED1B03A23A502AE5E05587F9AC9"),
        id_hex!("B1C1E0358671FE9744CD5F9E44CDF9CE"),
    ),
    (
        id_hex!("F493183CF6394511A59AFAEFF57AC46E"),
        id_hex!("B1CEA62A2E4CF10FF967B60A5B583380"),
    ),
];

const OMITTED_READ_AUDIT_CONTEXT: &str = "faculties.message-cutover.omitted-read-batch.v1";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
enum OmittedReadKind {
    Orphan = 1,
    SenderSelf = 2,
    ThirdPartyDirect = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuditedOmissionBatch {
    source_commit: &'static str,
    digest: &'static str,
    orphan_reads: usize,
    sender_self_reads: usize,
    third_party_direct_reads: usize,
}

// This table is deliberately a stopped-world allow-list rather than a general
// repair policy. Each digest covers the complete sorted source shapes of every
// omitted occurrence whose first authored completeness frontier is the named
// commit. A changed row, category, grouping, or source coordinate therefore
// fails before a destination is written.
const AUDITED_OMISSION_BATCHES: &[AuditedOmissionBatch] = &[
    AuditedOmissionBatch {
        source_commit: "07AE7A0FD93EBCF8DB8D941BCFD69EF3C9A74A4B4F5ED0D904230E76595FE44D",
        digest: "2CE5E34D75767C1F3A4F3B7A0A28642BFD03223D759F01FD7AB9431338D7E599",
        orphan_reads: 1,
        sender_self_reads: 0,
        third_party_direct_reads: 0,
    },
    AuditedOmissionBatch {
        source_commit: "15C2F4639664FFF333BA5C0D2C2E58760EC7045CC000D8C263DB5E4824B7908A",
        digest: "A9528BDA802DFD782A6D465EEAE0954BFA1204B9E4578D5A122DE7C23B4AD634",
        orphan_reads: 2,
        sender_self_reads: 12,
        third_party_direct_reads: 51,
    },
    AuditedOmissionBatch {
        source_commit: "7B882E39E4A6BA287A0342912C1842772584A7435E2086BF3D734EFE1A2CB1C1",
        digest: "3F4FC1629C7240A15A54C29668E0838D9D972AB6C0554C2F99005140F5A2C87B",
        orphan_reads: 1,
        sender_self_reads: 0,
        third_party_direct_reads: 0,
    },
    AuditedOmissionBatch {
        source_commit: "7FB5ABF8FEBA8FB408D8DAEA0F726F27028382B100C3E5E829BB323EB031BA60",
        digest: "591E49DB5E9770CB1DD18D812085F161DE4AB8C993907619237CF9C4541AB3E4",
        orphan_reads: 1,
        sender_self_reads: 0,
        third_party_direct_reads: 0,
    },
    AuditedOmissionBatch {
        source_commit: "A3ACA38AA3A4AB6E7FC6438BA28C82F527423C8DA1ECF37DED8226A968614E3F",
        digest: "BDF82CA07207ADCC4095CDEB26844656E1CDE9EE5371F2D6506D5D6D3C409A4A",
        orphan_reads: 1,
        sender_self_reads: 0,
        third_party_direct_reads: 0,
    },
    AuditedOmissionBatch {
        source_commit: "B7B847256E1D82A82A9599F5FC631AAEB12D9371FBEBD324B4E03DD72665E2D7",
        digest: "921E6277E3659F9DBB01DD2099AABC7E11248348B18BFF091A6CC30A615A7ED8",
        orphan_reads: 1,
        sender_self_reads: 0,
        third_party_direct_reads: 0,
    },
    AuditedOmissionBatch {
        source_commit: "BE3A8344E8FBB1CD7CC2B262F65A73333C26C40ED1842752FA08F39DC2B9F68A",
        digest: "EB17C273DEEA9A75C2273D3878AEEB1867B04FB545EFE0FC834CB5E85A8F4C95",
        orphan_reads: 1,
        sender_self_reads: 0,
        third_party_direct_reads: 0,
    },
    AuditedOmissionBatch {
        source_commit: "C2F0F9B91A84F760BAA0E3A9435EF3C55EE9ECED6A9DA8F3E546EF890D97D61B",
        digest: "F2843B83403EE91728512E83B87BBB701011BD9726C90606D4F86AD8C297C5F1",
        orphan_reads: 1,
        sender_self_reads: 0,
        third_party_direct_reads: 0,
    },
    AuditedOmissionBatch {
        source_commit: "C9AC9ECF82571BB36397BEF393B977324771F86648CEB8D501A1FEC385BE7923",
        digest: "7806957FE35598BFE4957AB9CC0700985C9F5440931669C30215550A4B26F7C3",
        orphan_reads: 1,
        sender_self_reads: 0,
        third_party_direct_reads: 0,
    },
    AuditedOmissionBatch {
        source_commit: "F10C028FBB2A430135B7A7F6491AC6ECAD00F0B8AC244E016093050D04BE2F4B",
        digest: "EA26F0068B32D6E0B2FE2688A57D83AFF115C3F8B62AC3B2A9EF2C62F02269A9",
        orphan_reads: 1,
        sender_self_reads: 0,
        third_party_direct_reads: 0,
    },
];

mod legacy {
    use super::*;

    attributes! {
        "2E26F8BA886495A8DF04ACF0ED3ACBD4" unsafe as short_name: ShortString;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LegacyMessage {
    id: Id,
    from: Id,
    to: Id,
    body: current::TextHandle,
    created_at: current::IntervalValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LegacyRead {
    id: Id,
    message: Id,
    reader: Id,
    observed_at: current::IntervalValue,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct LegacyCatalog {
    messages: BTreeMap<Id, LegacyMessage>,
    reads: BTreeMap<Id, LegacyRead>,
    orphan_reads: BTreeMap<Id, LegacyRead>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MessageMigrationReport {
    pub authored_commits: usize,
    pub authored_empty_commits: usize,
    pub contentless_merges: usize,
    pub original_facts: usize,
    pub preserved_original_facts: usize,
    pub added_canonical_facts: usize,
    pub legacy_messages: usize,
    pub canonical_messages: usize,
    pub legacy_read_occurrences: usize,
    pub excluded_orphan_reads: usize,
    pub excluded_sender_self_reads: usize,
    pub excluded_third_party_direct_reads: usize,
    pub canonical_reads: usize,
    pub emitted_message_occurrences: usize,
    pub emitted_read_occurrences: usize,
    pub output_facts: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
    preserved: Fragment,
}

impl MessageMigrationCommit {
    /// Exact authored content, metadata, and resident blobs that must remain
    /// present in [`Self::fragment`].
    pub fn preserved_fragment(&self) -> &Fragment {
        &self.preserved
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageMigrationPlan {
    message_source_pin: LegacyPinCoordinate,
    relations_source_pin: LegacyPinCoordinate,
    commits: Vec<MessageMigrationCommit>,
    relation_facts: TribleSet,
    original: TribleSet,
    additions: TribleSet,
    report: MessageMigrationReport,
}

impl MessageMigrationPlan {
    pub const fn message_source_pin(&self) -> LegacyPinCoordinate {
        self.message_source_pin
    }

    pub const fn relations_source_pin(&self) -> LegacyPinCoordinate {
        self.relations_source_pin
    }

    pub fn commits(&self) -> &[MessageMigrationCommit] {
        &self.commits
    }

    pub const fn report(&self) -> &MessageMigrationReport {
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
            bail!("Message migration classifies a legacy fact as a canonical addition");
        }
        let mut expected = self.original.clone();
        expected += self.additions.clone();
        if self.materialized_facts() != expected {
            bail!("planned Message collection is not exactly legacy facts union canonical shadows");
        }
        for commit in &self.commits {
            let mut retained = commit.fragment.clone();
            retained += commit.preserved.clone();
            if retained != commit.fragment {
                bail!(
                    "Message commit projected from {} dropped authored content, metadata, or resident blobs",
                    hex::encode_upper(commit.source.commit.raw)
                );
            }
        }
        if self.report.original_facts != self.original.len()
            || self.report.preserved_original_facts != self.original.len()
            || self.report.added_canonical_facts != self.additions.len()
            || self.report.output_facts != expected.len()
        {
            bail!("Message migration conservation report disagrees with the planned facts");
        }
        Ok(())
    }

    fn validate(&self, reader: &PileReader) -> Result<()> {
        self.verify_conservation()?;
        let mut complete = Fragment::empty();
        for commit in &self.commits {
            complete += commit.fragment.clone();
        }
        let validated = current::validate_catalog_union(
            reader,
            &TribleSet::new(),
            &complete,
            &self.relation_facts,
        )
        .context("validate planned Message collection and attachments")?;
        if validated != self.materialized_facts() {
            bail!("planned Message fragment union changed during validation");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MessageCommitPartition {
    source: LegacyCommitCoordinate,
    content: Fragment,
    metadata: Fragment,
    preserved: Fragment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PartitionedMessageRewrite {
    commits: Vec<MessageCommitPartition>,
    original: TribleSet,
    additions: TribleSet,
    report: MessageMigrationReport,
}

/// Plan the complete legacy Message branch without mutating either pile.
pub fn plan(source: &FrozenSource) -> Result<MessageMigrationPlan> {
    let relations_plan = relations_cutover::plan(source)
        .context("replay Relations for frozen Message recipients")?;
    plan_with_relations(source, &relations_plan)
}

/// Plan Message from an already-verified Relations projection of the same
/// frozen source.
///
/// Aggregate activation uses this path so the Relations DAG is replayed once
/// and the exact same projection both supplies Message recipient evidence and
/// becomes the native Relations collection.
pub(crate) fn plan_with_relations(
    source: &FrozenSource,
    relations_plan: &relations_cutover::RelationsMigrationPlan,
) -> Result<MessageMigrationPlan> {
    if !source.legacy_pins().contains(&relations_plan.source_pin()) {
        bail!("Relations migration plan does not belong to this frozen source");
    }
    let branch = source
        .legacy_branch(LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Message branch"))?;
    let authored = project_legacy_authored_commits(source, &branch, validate_legacy_payloads)
        .context("project frozen Message authored commits")?;
    let relation_facts = relations_plan.materialized_facts();
    let rewritten = rewrite_message_branch(&branch, &authored, source.reader(), &relation_facts)
        .context("add intrinsic Message shadows to the preserved authored DAG")?;
    let commits = rewritten
        .commits
        .into_iter()
        .map(|mut commit| {
            commit.content.describe_with(commit.metadata);
            MessageMigrationCommit {
                source: commit.source,
                fragment: commit.content,
                preserved: commit.preserved,
            }
        })
        .collect();
    let plan = MessageMigrationPlan {
        message_source_pin: branch.pin_coordinate(),
        relations_source_pin: relations_plan.source_pin(),
        commits,
        relation_facts,
        original: rewritten.original,
        additions: rewritten.additions,
        report: rewritten.report,
    };
    plan.validate(source.reader())?;
    Ok(plan)
}

/// Publish a frozen plan through the native Message collection facade.
pub fn publish(
    source: &FrozenSource,
    plan: &MessageMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    for source_pin in [plan.message_source_pin, plan.relations_source_pin] {
        if !source.legacy_pins().contains(&source_pin) {
            bail!("Message migration plan does not belong to this frozen source");
        }
    }
    plan.validate(source.reader())?;
    publish_fragments(
        target,
        key,
        schema::DEFAULT_SCOPE_ID,
        plan.commits.iter().map(|commit| commit.fragment.clone()),
    )
}

fn raw_values(facts: &TribleSet, entity: Id, attribute: Id) -> Vec<RawInline> {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity && fact.a() == &attribute)
        .map(|fact| {
            let mut raw = [0; 32];
            raw.copy_from_slice(&fact.data[V_START..]);
            raw
        })
        .collect()
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

fn ids(
    facts: &TribleSet,
    entity: Id,
    attribute: &Attribute<inlineencodings::GenId>,
) -> Result<Vec<Id>> {
    inline_values(facts, entity, attribute)
        .into_iter()
        .map(|value| {
            value.try_from_inline().map_err(|error| {
                anyhow!(
                    "decode legacy Message id on {entity:X} for {}: {error:?}",
                    attribute.id()
                )
            })
        })
        .collect()
}

fn exactly_one<T>(mut values: Vec<T>, entity: Id, field: &str) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "legacy Message entity {entity:X} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(values.pop().unwrap())
}

fn ordered_bounds(raw: RawInline, entity: Id, field: &str) -> Result<(i128, i128)> {
    let value: current::IntervalValue = Inline::new(raw);
    value
        .try_from_inline()
        .map_err(|error| anyhow!("decode ordered {field} on {entity:X}: {error:?}"))
}

fn legacy_le_bounds(raw: RawInline, entity: Id, field: &str) -> Result<(i128, i128)> {
    let lower = i128::from_le_bytes(raw[..16].try_into().unwrap());
    let upper = i128::from_le_bytes(raw[16..].try_into().unwrap());
    if lower > upper {
        bail!("legacy little-endian {field} on {entity:X} is inverted");
    }
    Ok((lower, upper))
}

fn ordered_interval(lower: i128, upper: i128) -> current::IntervalValue {
    const SIGN: u128 = 1u128 << 127;
    let mut raw = [0; 32];
    raw[..16].copy_from_slice(&((lower as u128) ^ SIGN).to_be_bytes());
    raw[16..].copy_from_slice(&((upper as u128) ^ SIGN).to_be_bytes());
    Inline::new(raw)
}

fn canonical_time(
    facts: &TribleSet,
    entity: Id,
    ordered_attributes: &[Id],
    legacy_le_attributes: &[Id],
    field: &str,
) -> Result<current::IntervalValue> {
    let mut observations = Vec::new();
    for attribute in ordered_attributes {
        let values = raw_values(facts, entity, *attribute);
        if values.len() > 1 {
            bail!(
                "legacy Message entity {entity:X} has repeated {field} values on attribute {attribute:X}"
            );
        }
        observations.extend(
            values
                .into_iter()
                .map(|raw| ordered_bounds(raw, entity, field))
                .collect::<Result<Vec<_>>>()?,
        );
    }
    for attribute in legacy_le_attributes {
        let values = raw_values(facts, entity, *attribute);
        if values.len() > 1 {
            bail!(
                "legacy Message entity {entity:X} has repeated {field} values on attribute {attribute:X}"
            );
        }
        observations.extend(
            values
                .into_iter()
                .map(|raw| legacy_le_bounds(raw, entity, field))
                .collect::<Result<Vec<_>>>()?,
        );
    }
    let first = observations
        .first()
        .copied()
        .ok_or_else(|| anyhow!("legacy Message entity {entity:X} has no {field}"))?;
    if observations.iter().any(|bounds| bounds != &first) {
        bail!("legacy Message entity {entity:X} has semantically conflicting {field} encodings");
    }
    if first.0 != first.1 {
        bail!("legacy Message entity {entity:X} has a non-point {field}");
    }
    Ok(ordered_interval(first.0, first.1))
}

fn expected_scaffolding() -> Fragment {
    // Preserve the exact reviewed private label without publishing its text in
    // the source tree. The stopped-world validator still compares the full
    // encoded fact, byte for byte.
    let local_agent_name_bytes = [0x6c, 0x69, 0x6f, 0x72, 0x61];
    let local_agent_name =
        std::str::from_utf8(&local_agent_name_bytes).expect("reviewed legacy label is valid UTF-8");
    let mut fragment = entity! { ExclusiveId::force_ref(&KIND_PARTY_ID) @
        legacy::short_name: "local_party",
    };
    fragment += entity! { ExclusiveId::force_ref(&PARTY_LOCAL_AGENT_ID) @
        metadata::tag: &KIND_PARTY_ID,
        legacy::short_name: local_agent_name,
    };
    fragment += entity! { ExclusiveId::force_ref(&PARTY_USER_ID) @
        metadata::tag: &KIND_PARTY_ID,
        legacy::short_name: "user",
    };
    fragment += entity! { ExclusiveId::force_ref(&KIND_MESSAGE_ID) @
        legacy::short_name: "local_message",
        metadata::name: "local_message",
    };
    fragment += entity! { ExclusiveId::force_ref(&KIND_READ_ID) @
        legacy::short_name: "local_read",
        metadata::name: "local_read",
    };
    fragment
}

fn canonical_party(id: Id) -> Id {
    if id == PARTY_USER_ID {
        PARTY_USER_SUCCESSOR_ID
    } else {
        id
    }
}

fn tagged_entities(facts: &TribleSet, wanted: Id) -> Result<BTreeSet<Id>> {
    let mut tagged = BTreeSet::new();
    for fact in facts.iter().filter(|fact| fact.a() == &metadata::tag.id()) {
        let value: Id = (*fact.v::<inlineencodings::GenId>())
            .try_from_inline()
            .map_err(|error| anyhow!("decode legacy Message tag on {:X}: {error:?}", fact.e()))?;
        if value == wanted {
            tagged.insert(*fact.e());
        }
    }
    Ok(tagged)
}

fn exact_tag(facts: &TribleSet, entity: Id, expected: Id, label: &str) -> Result<()> {
    let values = ids(facts, entity, &metadata::tag)?;
    let actual = exactly_one(values, entity, "metadata::tag")?;
    if actual != expected {
        bail!("legacy {label} {entity:X} has tag {actual:X}; expected {expected:X}");
    }
    Ok(())
}

fn require_only_attributes(
    facts: &TribleSet,
    entity: Id,
    allowed: &[Id],
    label: &str,
) -> Result<()> {
    for fact in facts.iter().filter(|fact| fact.e() == &entity) {
        if !allowed.contains(fact.a()) {
            bail!(
                "legacy {label} {entity:X} has unknown attribute {:X}",
                fact.a()
            );
        }
    }
    Ok(())
}

fn validate_scaffolding(facts: &TribleSet) -> Result<()> {
    let expected = expected_scaffolding();
    let scaffold_ids = BTreeSet::from([
        KIND_PARTY_ID,
        PARTY_LOCAL_AGENT_ID,
        PARTY_USER_ID,
        KIND_MESSAGE_ID,
        KIND_READ_ID,
    ]);
    let actual: TribleSet = facts
        .iter()
        .filter(|fact| scaffold_ids.contains(fact.e()))
        .copied()
        .collect();
    if actual != *expected.facts() {
        bail!(
            "legacy Message ontology scaffolding differs from the exact published shape ({} missing, {} unexpected facts)",
            expected.facts().difference(&actual).len(),
            actual.difference(expected.facts()).len(),
        );
    }
    Ok(())
}

fn load_legacy_catalog(reader: &PileReader, facts: &TribleSet) -> Result<LegacyCatalog> {
    validate_scaffolding(facts)?;
    let message_ids = tagged_entities(facts, KIND_MESSAGE_ID)?;
    let read_ids = tagged_entities(facts, KIND_READ_ID)?;
    if !message_ids.is_disjoint(&read_ids) {
        bail!("legacy Message entity is tagged as both a message and a read occurrence");
    }

    let scaffold_ids = BTreeSet::from([
        KIND_PARTY_ID,
        PARTY_LOCAL_AGENT_ID,
        PARTY_USER_ID,
        KIND_MESSAGE_ID,
        KIND_READ_ID,
    ]);
    for entity in facts.iter().map(|fact| *fact.e()).collect::<BTreeSet<_>>() {
        if !message_ids.contains(&entity)
            && !read_ids.contains(&entity)
            && !scaffold_ids.contains(&entity)
        {
            bail!("legacy Message catalog contains unknown entity {entity:X}");
        }
    }

    let message_attributes = [
        metadata::tag.id(),
        local::from.id(),
        local::to.id(),
        local::body.id(),
        metadata::created_at.id(),
        LEGACY_CREATED_AT_ORDERED,
        LEGACY_CREATED_AT_LE,
    ];
    let mut messages = BTreeMap::new();
    for id in message_ids {
        require_only_attributes(facts, id, &message_attributes, "message")?;
        exact_tag(facts, id, KIND_MESSAGE_ID, "message")?;
        let row = LegacyMessage {
            id,
            from: exactly_one(ids(facts, id, &local::from)?, id, "local::from")?,
            to: exactly_one(ids(facts, id, &local::to)?, id, "local::to")?,
            body: exactly_one(inline_values(facts, id, &local::body), id, "local::body")?,
            created_at: canonical_time(
                facts,
                id,
                &[metadata::created_at.id(), LEGACY_CREATED_AT_ORDERED],
                &[LEGACY_CREATED_AT_LE],
                "creation time",
            )?,
        };
        let _: anybytes::View<str> = reader.get(row.body).with_context(|| {
            format!(
                "read legacy Message body {} on {id:X}",
                hex::encode_upper(row.body.raw)
            )
        })?;
        messages.insert(id, row);
    }

    let read_attributes = [
        metadata::tag.id(),
        local::about_message.id(),
        local::reader.id(),
        local::read_at.id(),
        LEGACY_READ_AT_LE,
    ];
    let mut reads = BTreeMap::new();
    let mut orphan_reads = BTreeMap::new();
    for id in read_ids {
        require_only_attributes(facts, id, &read_attributes, "read occurrence")?;
        exact_tag(facts, id, KIND_READ_ID, "read occurrence")?;
        let row = LegacyRead {
            id,
            message: exactly_one(
                ids(facts, id, &local::about_message)?,
                id,
                "local::about_message",
            )?,
            reader: exactly_one(ids(facts, id, &local::reader)?, id, "local::reader")?,
            observed_at: canonical_time(
                facts,
                id,
                &[local::read_at.id()],
                &[LEGACY_READ_AT_LE],
                "read time",
            )?,
        };
        if messages.contains_key(&row.message) {
            reads.insert(id, row);
        } else if KNOWN_ORPHAN_READS.contains(&(id, row.message)) {
            orphan_reads.insert(id, row);
        } else {
            bail!(
                "legacy read occurrence {id:X} names unknown message {:X} and is not an audited orphan",
                row.message
            );
        }
    }

    Ok(LegacyCatalog {
        messages,
        reads,
        orphan_reads,
    })
}

fn validate_legacy_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts
        .iter()
        .filter(|fact| fact.a() == &local::body.id() || fact.a() == &metadata::name.id())
    {
        let handle = *fact.v::<Handle<LongString>>();
        let _: anybytes::View<str> = reader.get(handle).with_context(|| {
            format!(
                "strictly read legacy Message text payload {}",
                hex::encode_upper(handle.raw)
            )
        })?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct Supports {
    entity: Id,
    fields: Vec<Vec<usize>>,
}

fn ancestry_bits(
    branch: &FrozenLegacyBranch,
) -> Result<(Vec<Vec<u64>>, BTreeMap<[u8; 32], usize>)> {
    let words = branch.deltas.len().div_ceil(64);
    let mut index = BTreeMap::<[u8; 32], usize>::new();
    let mut closure = Vec::<Vec<u64>>::with_capacity(branch.deltas.len());
    for (position, delta) in branch.deltas.iter().enumerate() {
        let mut ancestors = vec![0u64; words];
        for parent in &delta.parents {
            let parent_index = index.get(&parent.raw).copied().ok_or_else(|| {
                anyhow!(
                    "legacy Message commit {} precedes parent {}",
                    hex::encode_upper(delta.commit.raw),
                    hex::encode_upper(parent.raw)
                )
            })?;
            for (target, source) in ancestors.iter_mut().zip(closure[parent_index].iter()) {
                *target |= source;
            }
        }
        ancestors[position / 64] |= 1u64 << (position % 64);
        if index.insert(delta.commit.raw, position).is_some() {
            bail!(
                "legacy Message branch repeats commit {}",
                hex::encode_upper(delta.commit.raw)
            );
        }
        closure.push(ancestors);
    }
    Ok((closure, index))
}

fn supported_at(supports: &Supports, ancestors: &[u64]) -> bool {
    supports.fields.iter().all(|witnesses| {
        witnesses
            .iter()
            .any(|index| ancestors[index / 64] & (1u64 << (index % 64)) != 0)
    })
}

fn emission_frontiers(
    branch: &FrozenLegacyBranch,
    closure: &[Vec<u64>],
    index: &BTreeMap<[u8; 32], usize>,
    supports: &Supports,
    label: &str,
) -> Result<Vec<usize>> {
    let mut frontiers = Vec::new();
    for (position, delta) in branch.deltas.iter().enumerate() {
        if !supported_at(supports, &closure[position]) {
            continue;
        }
        let parent_available = delta.parents.iter().any(|parent| {
            let parent_index = index[&parent.raw];
            supported_at(supports, &closure[parent_index])
        });
        if parent_available {
            continue;
        }
        if !delta.is_authored() {
            bail!(
                "legacy {label} {:X} becomes complete only at contentless merge {}",
                supports.entity,
                hex::encode_upper(delta.commit.raw)
            );
        }
        frontiers.push(position);
    }
    if frontiers.is_empty() {
        bail!(
            "legacy {label} {:X} has no authored completeness frontier",
            supports.entity
        );
    }
    Ok(frontiers)
}

fn support_field(attribute: Id, message: bool) -> Option<usize> {
    if attribute == metadata::tag.id() {
        Some(0)
    } else if message && attribute == local::from.id()
        || !message && attribute == local::about_message.id()
    {
        Some(1)
    } else if message && attribute == local::to.id() || !message && attribute == local::reader.id()
    {
        Some(2)
    } else if message && attribute == local::body.id() {
        Some(3)
    } else if message
        && [
            metadata::created_at.id(),
            LEGACY_CREATED_AT_ORDERED,
            LEGACY_CREATED_AT_LE,
        ]
        .contains(&attribute)
        || !message && [local::read_at.id(), LEGACY_READ_AT_LE].contains(&attribute)
    {
        Some(if message { 4 } else { 3 })
    } else {
        None
    }
}

fn supports_for(
    branch: &FrozenLegacyBranch,
    entities: impl IntoIterator<Item = Id>,
    message: bool,
) -> BTreeMap<Id, Supports> {
    let mut supports: BTreeMap<Id, Supports> = entities
        .into_iter()
        .map(|entity| {
            (
                entity,
                Supports {
                    entity,
                    fields: (0..if message { 5 } else { 4 })
                        .map(|_| Vec::new())
                        .collect(),
                },
            )
        })
        .collect();
    for (index, delta) in branch.deltas.iter().enumerate() {
        for fact in &delta.facts {
            let Some(record) = supports.get_mut(fact.e()) else {
                continue;
            };
            if let Some(field) = support_field(*fact.a(), message) {
                record.fields[field].push(index);
            }
        }
    }
    supports
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedOmissionBatch {
    digest: String,
    orphan_reads: usize,
    sender_self_reads: usize,
    third_party_direct_reads: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct OmissionAudit {
    omitted: BTreeSet<Id>,
    orphan_reads: usize,
    sender_self_reads: usize,
    third_party_direct_reads: usize,
}

fn classify_omitted_reads(
    catalog: &LegacyCatalog,
    relation_facts: &TribleSet,
) -> Result<BTreeMap<Id, OmittedReadKind>> {
    let people = relations::person_anchors(relation_facts);
    let identities = relations::IdentityComponents::from_facts(relation_facts)?;
    let mut kinds = BTreeMap::new();
    for row in catalog.orphan_reads.values() {
        kinds.insert(row.id, OmittedReadKind::Orphan);
    }
    for row in catalog.reads.values() {
        let message = &catalog.messages[&row.message];
        let from = canonical_party(message.from);
        let to = canonical_party(message.to);
        let reader = canonical_party(row.reader);
        if !people.contains(&reader) {
            bail!(
                "legacy read occurrence {:X} names reader {reader:X} absent from canonical Relations",
                row.id
            );
        }
        let kind = if identities.equivalent(from, reader)? {
            Some(OmittedReadKind::SenderSelf)
        } else if people.contains(&to) && !identities.equivalent(to, reader)? {
            Some(OmittedReadKind::ThirdPartyDirect)
        } else {
            None
        };
        if let Some(kind) = kind {
            kinds.insert(row.id, kind);
        }
    }
    Ok(kinds)
}

fn omission_batch_digest(
    source_commit: [u8; 32],
    occurrences: &[(OmittedReadKind, Id)],
    source_union: &TribleSet,
) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(OMITTED_READ_AUDIT_CONTEXT);
    hasher.update(&source_commit);
    for (kind, id) in occurrences {
        hasher.update(&[*kind as u8]);
        hasher.update(&id.raw());
        let mut shape: Vec<_> = source_union
            .iter()
            .filter(|fact| fact.e() == id)
            .map(|fact| fact.data)
            .collect();
        shape.sort_unstable();
        hasher.update(&(shape.len() as u64).to_be_bytes());
        for fact in shape {
            hasher.update(&fact);
        }
    }
    hex::encode_upper(hasher.finalize().as_bytes())
}

fn format_observed_omission_batches(observed: &BTreeMap<String, ObservedOmissionBatch>) -> String {
    observed
        .iter()
        .map(|(commit, batch)| {
            format!(
                "{commit}:{}:orphan={}:sender_self={}:third_party_direct={}",
                batch.digest,
                batch.orphan_reads,
                batch.sender_self_reads,
                batch.third_party_direct_reads
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn audit_omitted_reads(
    branch: &FrozenLegacyBranch,
    closure: &[Vec<u64>],
    commit_index: &BTreeMap<[u8; 32], usize>,
    read_supports: &BTreeMap<Id, Supports>,
    source_union: &TribleSet,
    catalog: &LegacyCatalog,
    relation_facts: &TribleSet,
) -> Result<OmissionAudit> {
    let kinds = classify_omitted_reads(catalog, relation_facts)?;
    if kinds.is_empty() {
        return Ok(OmissionAudit::default());
    }
    let mut by_commit = BTreeMap::<[u8; 32], Vec<(OmittedReadKind, Id)>>::new();
    for (id, kind) in &kinds {
        let supports = read_supports
            .get(id)
            .ok_or_else(|| anyhow!("omitted legacy read {id:X} has no support census"))?;
        for frontier in emission_frontiers(
            branch,
            closure,
            commit_index,
            supports,
            "omitted read occurrence",
        )? {
            by_commit
                .entry(branch.deltas[frontier].commit.raw)
                .or_default()
                .push((*kind, *id));
        }
    }

    let mut observed = BTreeMap::new();
    for (commit, mut occurrences) in by_commit {
        occurrences.sort_unstable();
        occurrences.dedup();
        let mut batch = ObservedOmissionBatch {
            digest: omission_batch_digest(commit, &occurrences, source_union),
            orphan_reads: 0,
            sender_self_reads: 0,
            third_party_direct_reads: 0,
        };
        for (kind, _) in &occurrences {
            match kind {
                OmittedReadKind::Orphan => batch.orphan_reads += 1,
                OmittedReadKind::SenderSelf => batch.sender_self_reads += 1,
                OmittedReadKind::ThirdPartyDirect => batch.third_party_direct_reads += 1,
            }
        }
        observed.insert(hex::encode_upper(commit), batch);
    }

    let expected: BTreeMap<&str, &AuditedOmissionBatch> = AUDITED_OMISSION_BATCHES
        .iter()
        .map(|batch| (batch.source_commit, batch))
        .collect();
    let exact = observed.len() == expected.len()
        && observed.iter().all(|(commit, actual)| {
            expected.get(commit.as_str()).is_some_and(|wanted| {
                actual.digest == wanted.digest
                    && actual.orphan_reads == wanted.orphan_reads
                    && actual.sender_self_reads == wanted.sender_self_reads
                    && actual.third_party_direct_reads == wanted.third_party_direct_reads
            })
        });
    if !exact {
        bail!(
            "legacy Message omitted-read audit differs from its exact source-bound allow-list; observed [{}]",
            format_observed_omission_batches(&observed)
        );
    }

    Ok(OmissionAudit {
        omitted: kinds.keys().copied().collect(),
        orphan_reads: kinds
            .values()
            .filter(|kind| **kind == OmittedReadKind::Orphan)
            .count(),
        sender_self_reads: kinds
            .values()
            .filter(|kind| **kind == OmittedReadKind::SenderSelf)
            .count(),
        third_party_direct_reads: kinds
            .values()
            .filter(|kind| **kind == OmittedReadKind::ThirdPartyDirect)
            .count(),
    })
}

fn snapshot_descends_from(
    snapshots: &BTreeMap<Id, relations::GroupSnapshot>,
    descendant: Id,
    ancestor: Id,
) -> bool {
    let mut pending = vec![descendant];
    let mut seen = BTreeSet::new();
    while let Some(next) = pending.pop() {
        if !seen.insert(next) {
            continue;
        }
        let Some(snapshot) = snapshots.get(&next) else {
            continue;
        };
        for predecessor in &snapshot.predecessors {
            if predecessor == &ancestor {
                return true;
            }
            pending.push(*predecessor);
        }
    }
    false
}

/// Select a pre-existing Relations snapshot using only causal group ancestry
/// and read evidence. A read constrains membership positively; absence of a
/// read says nothing. No clock or iteration order participates.
fn reconstructed_group_snapshot(
    relation_facts: &TribleSet,
    group: Id,
    sender: Id,
    readers: &BTreeSet<Id>,
) -> Result<Id> {
    if readers.is_empty() {
        return Ok(relations::current_group(relation_facts, group)?.id);
    }
    let identities = relations::IdentityComponents::from_facts(relation_facts)?;
    for reader in readers {
        if identities.equivalent(sender, *reader)? {
            bail!(
                "group message sender {sender:X} also has a read occurrence under identity {:X}",
                reader
            );
        }
    }

    let mut snapshots = BTreeMap::new();
    for id in tagged_entities(relation_facts, KIND_GROUP_SNAPSHOT)? {
        let snapshot = relations::group_snapshot(relation_facts, id)?;
        if snapshot.group == group {
            snapshots.insert(id, snapshot);
        }
    }
    let mut covering = BTreeSet::new();
    for (id, snapshot) in &snapshots {
        let mut covers_all = true;
        for reader in readers {
            let mut covered = false;
            for member in &snapshot.members {
                if identities.equivalent(*member, *reader)? {
                    covered = true;
                    break;
                }
            }
            if !covered {
                covers_all = false;
                break;
            }
        }
        if covers_all {
            covering.insert(*id);
        }
    }
    if covering.is_empty() {
        bail!(
            "group {group:X} has no authored Relations snapshot covering all {} historical readers",
            readers.len()
        );
    }

    let maximal: Vec<Id> = covering
        .iter()
        .copied()
        .filter(|candidate| {
            !covering.iter().copied().any(|other| {
                other != *candidate && snapshot_descends_from(&snapshots, other, *candidate)
            })
        })
        .collect();
    match maximal.as_slice() {
        [snapshot] => Ok(*snapshot),
        _ => bail!(
            "group {group:X} has {} incomparable ancestry-maximal snapshots covering the historical readers: {}",
            maximal.len(),
            maximal
                .iter()
                .map(|id| format!("{id:X}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Preserve each authored legacy fragment and partition canonical Message
/// shadows over its exact completeness frontiers. `relation_facts` must be the
/// canonical catalog produced by the same Relations cutover replay that will
/// enter the candidate.
fn rewrite_message_branch(
    branch: &FrozenLegacyBranch,
    authored: &[ProjectedLegacyCommit],
    reader: &PileReader,
    relation_facts: &TribleSet,
) -> Result<PartitionedMessageRewrite> {
    let expected_authored: Vec<CommitHandle> = branch
        .deltas
        .iter()
        .filter(|delta| delta.is_authored())
        .map(|delta| delta.commit)
        .collect();
    let actual_authored: Vec<CommitHandle> =
        authored.iter().map(|commit| commit.source.commit).collect();
    if actual_authored != expected_authored {
        bail!("legacy Message authored commits do not match the frozen repository DAG");
    }
    for commit in authored {
        if commit.source.branch != branch.branch || commit.source.pin != branch.pin {
            bail!("legacy Message authored commit belongs to another frozen pin");
        }
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
        bail!("projected Message authored facts differ from the frozen repository DAG");
    }
    let catalog = load_legacy_catalog(reader, &source_union)?;
    // These are coordinates in the complete repository DAG, including
    // contentless merge nodes. They are not interchangeable with the authored
    // output slots constructed below.
    let (closure, dag_commit_index) = ancestry_bits(branch)?;
    let message_supports = supports_for(branch, catalog.messages.keys().copied(), true);
    let read_supports = supports_for(
        branch,
        catalog
            .reads
            .keys()
            .chain(catalog.orphan_reads.keys())
            .copied(),
        false,
    );
    let omission_audit = audit_omitted_reads(
        branch,
        &closure,
        &dag_commit_index,
        &read_supports,
        &source_union,
        &catalog,
        relation_facts,
    )?;

    let mut commits: Vec<MessageCommitPartition> = authored
        .iter()
        .map(|commit| {
            let mut preserved = commit.content.clone();
            preserved.describe_with(commit.metadata.clone());
            MessageCommitPartition {
                source: commit.source,
                content: commit.content.clone(),
                metadata: commit.metadata.clone(),
                preserved,
            }
        })
        .collect();
    let output_commit_index: BTreeMap<[u8; 32], usize> = commits
        .iter()
        .enumerate()
        .map(|(index, commit)| (commit.source.commit.raw, index))
        .collect();

    let people = relations::person_anchors(relation_facts);
    let groups = relations::group_anchors(relation_facts);
    let mut readers_by_message = BTreeMap::<Id, BTreeSet<Id>>::new();
    for read in catalog
        .reads
        .values()
        .filter(|read| !omission_audit.omitted.contains(&read.id))
    {
        readers_by_message
            .entry(read.message)
            .or_default()
            .insert(canonical_party(read.reader));
    }
    let no_readers = BTreeSet::new();
    let mut canonical_shadows = TribleSet::new();
    let mut canonical_message_ids = BTreeSet::new();
    let mut message_ids = BTreeMap::<Id, Id>::new();
    let mut emitted_message_occurrences = 0usize;
    for row in catalog.messages.values() {
        let from = canonical_party(row.from);
        let to = canonical_party(row.to);
        if !people.contains(&from) {
            bail!(
                "legacy message {:X} names sender {:X} absent from canonical Relations",
                row.id,
                from
            );
        }
        let (snapshot, basis) = match (people.contains(&to), groups.contains(&to)) {
            (true, false) => (None, None),
            (false, true) => {
                let snapshot = reconstructed_group_snapshot(
                    relation_facts,
                    to,
                    from,
                    readers_by_message.get(&row.id).unwrap_or(&no_readers),
                )
                .with_context(|| {
                    format!(
                        "freeze reconstructed audience of legacy group message {:X}",
                        row.id
                    )
                })?;
                (
                    Some(snapshot),
                    Some(GROUP_SNAPSHOT_BASIS_CUTOVER_RECONSTRUCTED),
                )
            }
            (false, false) => bail!(
                "legacy message {:X} recipient {:X} is absent from canonical Relations",
                row.id,
                to
            ),
            (true, true) => bail!(
                "legacy message {:X} recipient {:X} is both a person and a group",
                row.id,
                to
            ),
        };
        let envelope =
            current::envelope_fragment(from, to, row.body, row.created_at, snapshot, basis);
        let canonical_message = envelope
            .root()
            .expect("canonical Message envelope has exactly one intrinsic root");
        canonical_shadows += envelope.facts().clone();
        message_ids.insert(row.id, canonical_message);
        canonical_message_ids.insert(canonical_message);
        let frontiers = emission_frontiers(
            branch,
            &closure,
            &dag_commit_index,
            &message_supports[&row.id],
            "message",
        )?;
        for frontier in frontiers {
            let commit = branch.deltas[frontier].commit.raw;
            commits[output_commit_index[&commit]].content += envelope.clone();
            emitted_message_occurrences += 1;
        }
    }

    let mut canonical_read_ids = BTreeSet::new();
    let mut emitted_read_occurrences = 0usize;
    for row in catalog
        .reads
        .values()
        .filter(|row| !omission_audit.omitted.contains(&row.id))
    {
        let frontiers = emission_frontiers(
            branch,
            &closure,
            &dag_commit_index,
            &read_supports[&row.id],
            "read occurrence",
        )?;
        let reader = canonical_party(row.reader);
        let message = message_ids.get(&row.message).copied().ok_or_else(|| {
            anyhow!(
                "legacy read occurrence {:X} has no canonical message mapping for {:X}",
                row.id,
                row.message
            )
        })?;
        let canonical_id = current::read_id(message, reader);
        canonical_read_ids.insert(canonical_id);
        for frontier in frontiers {
            let commit = branch.deltas[frontier].commit.raw;
            let (fragment, id) = current::read_fragment(message, reader, Some(row.observed_at));
            debug_assert_eq!(id, canonical_id);
            canonical_shadows += fragment.facts().clone();
            commits[output_commit_index[&commit]].content += fragment;
            emitted_read_occurrences += 1;
        }
    }

    let mut complete = Fragment::empty();
    let mut output_facts = TribleSet::new();
    for commit in &commits {
        output_facts += commit.content.facts().clone();
        complete += commit.content.clone();
    }
    // A stopped source may already contain one or more canonical shadow
    // facts. Set-union replay keeps those authored facts where they were and
    // classifies only the genuinely new portion as additions.
    let canonical_additions = canonical_shadows.difference(&source_union);
    let mut expected_output = source_union.clone();
    expected_output += canonical_additions.clone();
    if output_facts != expected_output {
        bail!("Message rewrite is not exactly legacy facts union canonical shadows");
    }
    current::validate_catalog_union(reader, &TribleSet::new(), &complete, relation_facts)
        .context("validate reconstructed Message catalog and attachments")?;
    if current::load_message_rows(&output_facts)?.len() != canonical_message_ids.len() {
        bail!("canonical Message reconstruction changed the intrinsic envelope census");
    }
    if current::load_read_rows(&output_facts)?.len() != canonical_read_ids.len() {
        bail!("canonical Message reconstruction changed the semantic read census");
    }

    let report = MessageMigrationReport {
        authored_commits: commits.len(),
        authored_empty_commits: commits
            .iter()
            .filter(|commit| commit.preserved.facts().is_empty())
            .count(),
        contentless_merges: branch
            .deltas
            .iter()
            .filter(|delta| !delta.is_authored())
            .count(),
        original_facts: source_union.len(),
        preserved_original_facts: source_union
            .iter()
            .filter(|fact| output_facts.contains(fact))
            .count(),
        added_canonical_facts: canonical_additions.len(),
        legacy_messages: catalog.messages.len(),
        canonical_messages: canonical_message_ids.len(),
        legacy_read_occurrences: catalog.reads.len() + catalog.orphan_reads.len(),
        excluded_orphan_reads: omission_audit.orphan_reads,
        excluded_sender_self_reads: omission_audit.sender_self_reads,
        excluded_third_party_direct_reads: omission_audit.third_party_direct_reads,
        canonical_reads: canonical_read_ids.len(),
        emitted_message_occurrences,
        emitted_read_occurrences,
        output_facts: output_facts.len(),
    };
    Ok(PartitionedMessageRewrite {
        commits,
        original: source_union,
        additions: canonical_additions,
        report,
    })
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace::core::blob::{Blob, IntoBlob, TryFromBlob};
    use triblespace::core::id::ExclusiveId;
    use triblespace::core::repo::{BlobStore, BlobStoreGet, PinStore, Repository};
    use triblespace::core::trible::Trible;
    use triblespace::macros::{entity, find, pattern};

    use super::*;
    use crate::collection_cutover::{
        discover_target, freeze_source, initialize_signer, open_pile_strict,
    };
    use crate::schemas::relations::KIND_PERSON_ID;

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-message-cutover-{}-{serial}",
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

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn raw_fact(entity: Id, attribute: Id, value: RawInline) -> Trible {
        let mut data = [0; 64];
        data[..16].copy_from_slice(&entity.raw());
        data[16..32].copy_from_slice(&attribute.raw());
        data[32..].copy_from_slice(&value);
        Trible::force_raw(data).unwrap()
    }

    fn insert_raw(facts: &mut TribleSet, entity: Id, attribute: Id, value: RawInline) {
        facts.insert(&raw_fact(entity, attribute, value));
    }

    #[test]
    fn scaffold_audit_is_independent_of_patch_or_archive_representation() {
        let patch = expected_scaffolding().facts().clone();
        assert_eq!(patch.len(), 9);
        let archive: Blob<SimpleArchive> = patch.clone().to_blob();
        let archive_backed = TribleSet::try_from_blob(archive).unwrap();
        assert_eq!(archive_backed, patch);
        validate_scaffolding(&patch).unwrap();
        validate_scaffolding(&archive_backed).unwrap();
    }

    #[test]
    fn redundant_timestamp_encodings_must_agree_and_be_points() {
        let entity = id(0x22);
        let point = 123_456_i128;
        let ordered = ordered_interval(point, point);
        let mut little = [0; 32];
        little[..16].copy_from_slice(&point.to_le_bytes());
        little[16..].copy_from_slice(&point.to_le_bytes());

        let mut facts = TribleSet::new();
        insert_raw(&mut facts, entity, metadata::created_at.id(), ordered.raw);
        insert_raw(&mut facts, entity, LEGACY_CREATED_AT_LE, little);
        assert_eq!(
            canonical_time(
                &facts,
                entity,
                &[metadata::created_at.id()],
                &[LEGACY_CREATED_AT_LE],
                "creation time"
            )
            .unwrap()
            .raw,
            ordered.raw
        );

        let different = point + 1;
        let mut conflicting = [0; 32];
        conflicting[..16].copy_from_slice(&different.to_le_bytes());
        conflicting[16..].copy_from_slice(&different.to_le_bytes());
        let mut conflict_facts = TribleSet::new();
        insert_raw(
            &mut conflict_facts,
            entity,
            metadata::created_at.id(),
            ordered.raw,
        );
        insert_raw(
            &mut conflict_facts,
            entity,
            LEGACY_CREATED_AT_LE,
            conflicting,
        );
        assert!(canonical_time(
            &conflict_facts,
            entity,
            &[metadata::created_at.id()],
            &[LEGACY_CREATED_AT_LE],
            "creation time"
        )
        .unwrap_err()
        .to_string()
        .contains("semantically conflicting"));

        let interval = ordered_interval(point, point + 1);
        let mut interval_facts = TribleSet::new();
        insert_raw(
            &mut interval_facts,
            entity,
            metadata::created_at.id(),
            interval.raw,
        );
        assert!(canonical_time(
            &interval_facts,
            entity,
            &[metadata::created_at.id()],
            &[],
            "creation time"
        )
        .unwrap_err()
        .to_string()
        .contains("non-point"));
    }

    #[test]
    fn omission_digest_is_order_independent_and_shape_sensitive() {
        let occurrence = id(0x23);
        let first_attribute = id(0x24);
        let second_attribute = id(0x25);
        let mut first = TribleSet::new();
        insert_raw(&mut first, occurrence, first_attribute, [0x31; 32]);
        insert_raw(&mut first, occurrence, second_attribute, [0x32; 32]);
        let mut reversed = TribleSet::new();
        insert_raw(&mut reversed, occurrence, second_attribute, [0x32; 32]);
        insert_raw(&mut reversed, occurrence, first_attribute, [0x31; 32]);
        let records = [(OmittedReadKind::SenderSelf, occurrence)];
        let digest = omission_batch_digest([0x41; 32], &records, &first);
        assert_eq!(
            digest,
            omission_batch_digest([0x41; 32], &records, &reversed)
        );

        let mut changed = first.clone();
        insert_raw(&mut changed, occurrence, id(0x26), [0x33; 32]);
        assert_ne!(
            digest,
            omission_batch_digest([0x41; 32], &records, &changed)
        );
        assert_ne!(digest, omission_batch_digest([0x42; 32], &records, &first));
    }

    #[test]
    fn reader_evidence_selects_only_a_unique_ancestry_maximum() {
        let sender = id(0x30);
        let first_reader = id(0x31);
        let second_reader = id(0x32);
        let group = id(0x33);
        let mut relations = entity! { ExclusiveId::force_ref(&sender) @
            metadata::tag: &KIND_PERSON_ID,
        };
        relations += entity! { ExclusiveId::force_ref(&first_reader) @
            metadata::tag: &KIND_PERSON_ID,
        };
        relations += entity! { ExclusiveId::force_ref(&second_reader) @
            metadata::tag: &KIND_PERSON_ID,
        };
        let (created, empty_snapshot) = relations::group_create_fragment(group, "group").unwrap();
        relations += created;
        let first =
            relations::group_snapshot_fragment(group, "group", &[first_reader], &[empty_snapshot])
                .unwrap();
        let first_snapshot = first.root().unwrap();
        relations += first;
        let latest = relations::group_snapshot_fragment(
            group,
            "group",
            &[first_reader, second_reader],
            &[first_snapshot],
        )
        .unwrap();
        let latest_snapshot = latest.root().unwrap();
        relations += latest;

        let readers = BTreeSet::from([first_reader]);
        assert_eq!(
            reconstructed_group_snapshot(relations.facts(), group, sender, &readers).unwrap(),
            latest_snapshot
        );

        let fork = relations::group_snapshot_fragment(
            group,
            "renamed group",
            &[first_reader],
            &[empty_snapshot],
        )
        .unwrap();
        relations += fork;
        assert!(
            reconstructed_group_snapshot(relations.facts(), group, sender, &readers)
                .unwrap_err()
                .to_string()
                .contains("incomparable ancestry-maximal snapshots")
        );
    }

    #[test]
    fn native_migration_is_strictly_additive_and_preserves_forks_metadata_and_source_pins() {
        let directory = TestDirectory::new();
        let source_path = directory.0.join("legacy.pile");
        let target_path = directory.0.join("target.pile");
        let key_path = directory.0.join("target.key");
        File::create(&source_path).unwrap();
        File::create(&target_path).unwrap();

        let pile = open_pile_strict(&source_path).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0x81; 32]), Fragment::empty()).unwrap();
        let relations_branch = *repository.create_branch("relations", None).unwrap();
        let sender = id(0x82);
        let recipient = id(0x83);
        let mut relations_fragment = entity! { ExclusiveId::force_ref(&sender) @
            metadata::tag: &KIND_PERSON_ID,
            metadata::name: "sender",
        };
        relations_fragment += entity! { ExclusiveId::force_ref(&recipient) @
            metadata::tag: &KIND_PERSON_ID,
            metadata::name: "recipient",
        };
        let mut relations_workspace = repository.pull(relations_branch).unwrap();
        relations_workspace.commit(relations_fragment, "legacy people");
        repository.push(&mut relations_workspace).unwrap();

        let message_branch = *repository.create_branch(LEGACY_BRANCH_NAME, None).unwrap();
        let old_message = id(0x84);
        let mut message_root = expected_scaffolding();
        let body = message_root.put("legacy body".to_owned());
        let canonical_envelope = current::envelope_fragment(
            sender,
            recipient,
            body,
            ordered_interval(10, 10),
            None,
            None,
        );
        let canonical_message = canonical_envelope.root().unwrap();
        message_root += entity! { ExclusiveId::force_ref(&old_message) @
            metadata::tag: &KIND_MESSAGE_ID,
            local::from: sender,
            local::to: recipient,
            local::body: body,
            metadata::created_at: ordered_interval(10, 10),
        };
        // Set-union additivity must also tolerate a canonical shadow already
        // authored in the source instead of reporting a collision or counting
        // those existing facts as new additions.
        message_root += canonical_envelope;
        let mut root_workspace = repository.pull(message_branch).unwrap();
        root_workspace.commit_with_metadata(
            message_root,
            entity! { metadata::description: "legacy message root metadata" },
            "legacy message",
        );
        repository.push(&mut root_workspace).unwrap();

        // Two authored read observations fork from one message commit. The
        // second push creates a contentless merge, which remains ancestry only.
        let mut left = repository.pull(message_branch).unwrap();
        let mut right = repository.pull(message_branch).unwrap();
        let left_read = id(0x85);
        let right_read = id(0x86);
        left.commit(
            entity! { ExclusiveId::force_ref(&left_read) @
                metadata::tag: &KIND_READ_ID,
                local::about_message: old_message,
                local::reader: recipient,
                local::read_at: ordered_interval(20, 20),
            },
            "left read",
        );
        right.commit(
            entity! { ExclusiveId::force_ref(&right_read) @
                metadata::tag: &KIND_READ_ID,
                local::about_message: old_message,
                local::reader: recipient,
                local::read_at: ordered_interval(30, 30),
            },
            "right read",
        );
        repository.push(&mut left).unwrap();
        repository.push(&mut right).unwrap();
        repository.close().unwrap();

        let frozen = freeze_source(&source_path).unwrap();
        let standalone_plan = plan(&frozen).unwrap();
        let relations_plan = relations_cutover::plan(&frozen).unwrap();
        let plan = plan_with_relations(&frozen, &relations_plan).unwrap();
        assert_eq!(plan, standalone_plan);
        plan.verify_conservation().unwrap();
        assert!(frozen.legacy_pins().contains(&plan.message_source_pin()));
        assert!(frozen.legacy_pins().contains(&plan.relations_source_pin()));
        assert_eq!(plan.relations_source_pin(), relations_plan.source_pin());
        assert_eq!(plan.report().authored_commits, 3);
        assert_eq!(plan.report().contentless_merges, 1);
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
            plan.report().output_facts,
            plan.original_facts().len() + plan.added_facts().len()
        );
        assert_eq!(plan.report().legacy_messages, 2);
        assert_eq!(plan.report().canonical_messages, 1);
        assert_eq!(plan.report().canonical_reads, 1);
        assert_eq!(plan.report().emitted_read_occurrences, 2);
        for commit in plan.commits() {
            let mut retained = commit.fragment.clone();
            retained += commit.preserved_fragment().clone();
            assert_eq!(retained, commit.fragment);
        }

        let facts = plan.materialized_facts();
        for fact in plan.original_facts() {
            assert!(facts.contains(fact));
        }
        for legacy_id in [old_message, left_read, right_read] {
            assert!(plan
                .original_facts()
                .iter()
                .any(|fact| fact.e() == &legacy_id));
            assert!(facts.iter().any(|fact| fact.e() == &legacy_id));
        }
        let message = current::load_message_rows(&facts).unwrap()[0];
        assert_eq!(message.id, canonical_message);
        assert_ne!(message.id, old_message);
        assert_eq!(current::load_message_rows(&facts).unwrap().len(), 1);
        let overlapping_fact = current::envelope_fragment(
            sender,
            recipient,
            body,
            ordered_interval(10, 10),
            None,
            None,
        )
        .facts()
        .iter()
        .find(|fact| fact.a() == &local::from.id())
        .copied()
        .unwrap();
        assert!(plan.original_facts().contains(&overlapping_fact));
        assert!(!plan.added_facts().contains(&overlapping_fact));
        let reads = current::load_read_rows(&facts).unwrap();
        assert_eq!(reads.len(), 1);
        assert!(![left_read, right_read].contains(&reads[0].id));
        assert_eq!(reads[0].message, message.id);
        assert_eq!(
            find!(
                observed: current::IntervalValue,
                pattern!(&facts, [{ reads[0].id @ local::read_at: ?observed }])
            )
            .count(),
            2
        );

        initialize_signer(&target_path, Some(&key_path)).unwrap();
        relations_cutover::publish(&frozen, &relations_plan, &target_path, Some(&key_path))
            .unwrap();
        let first = publish(&frozen, &plan, &target_path, Some(&key_path)).unwrap();
        let length = fs::metadata(&target_path).unwrap().len();
        let second = publish(&frozen, &plan, &target_path, Some(&key_path)).unwrap();
        assert_eq!(first, second);
        assert_eq!(fs::metadata(&target_path).unwrap().len(), length);

        let signer = crate::collection_cutover::load_signer(&target_path, Some(&key_path)).unwrap();
        let mut target = open_pile_strict(&target_path).unwrap();
        assert!(target
            .pins()
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
            .is_empty());
        let discovery = discover_target(&mut target, schema::DEFAULT_SCOPE_ID).unwrap();
        assert_eq!(discovery.commits().len(), 3);
        let commits = discovery.commits().to_vec();
        let mut collection = triblespace::core::collection::Collection::new(
            target,
            schema::DEFAULT_SCOPE_ID,
            signer,
        );
        let target_facts = collection.materialize().unwrap();
        for fact in plan.original_facts() {
            assert!(target_facts.contains(fact));
        }
        assert_eq!(current::load_message_rows(&target_facts).unwrap().len(), 1);
        assert_eq!(current::load_read_rows(&target_facts).unwrap().len(), 1);
        let reader = collection.storage_mut().reader().unwrap();
        current::validate_catalog(&reader, &target_facts, &relations_plan.materialized_facts())
            .unwrap();
        assert_eq!(
            current::read_body(&reader, message.body).unwrap(),
            "legacy body"
        );

        let mut metadata_facts = TribleSet::new();
        for commit in commits {
            metadata_facts += reader
                .get::<TribleSet, SimpleArchive>(commit.metadata())
                .unwrap();
        }
        let descriptions: BTreeSet<String> = find!(
            description: current::TextHandle,
            pattern!(&metadata_facts, [{ _?entity @ metadata::description: ?description }])
        )
        .map(|handle| {
            reader
                .get::<anybytes::View<str>, _>(handle)
                .unwrap()
                .to_string()
        })
        .collect();
        assert!(descriptions.contains("legacy message root metadata"));
        drop(reader);
        collection.into_storage().close().unwrap();

        // The operational cutover appends beside the frozen legacy branches.
        // Native publication must neither consume nor rewrite those pins.
        relations_cutover::publish(&frozen, &relations_plan, &source_path, Some(&key_path))
            .unwrap();
        let in_place_first = publish(&frozen, &plan, &source_path, Some(&key_path)).unwrap();
        let in_place_length = fs::metadata(&source_path).unwrap().len();
        let in_place_second = publish(&frozen, &plan, &source_path, Some(&key_path)).unwrap();
        assert_eq!(in_place_first, in_place_second);
        assert_eq!(fs::metadata(&source_path).unwrap().len(), in_place_length);

        let source_pin = plan.message_source_pin();
        let mut source = open_pile_strict(&source_path).unwrap();
        assert_eq!(source.head(source_pin.id).unwrap(), Some(source_pin.value));
        assert_eq!(
            discover_target(&mut source, schema::DEFAULT_SCOPE_ID)
                .unwrap()
                .commits()
                .len(),
            3
        );
        source.close().unwrap();
    }
}
