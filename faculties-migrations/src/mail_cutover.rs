//! Strictly additive stopped-world migration of the legacy Mail branch.
//!
//! Every authored Repository commit becomes one native Mail collection
//! commit, including authored empty commits. Contentless merge nodes remain
//! verified source ancestry and create no target authority. Original facts,
//! ids, semantic commit metadata, and resident attachment closure are copied
//! exactly. Current imported-observation and read shadows are added beside
//! that inert evidence; no historical Mail-owned credential envelope is
//! migrated into a current Secrets vault.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet};
use triblespace::prelude::*;

use crate::collection_cutover::{
    project_legacy_authored_commits, FrozenLegacyBranch, FrozenSource, LegacyCommitCoordinate,
    LegacyPinCoordinate, ProjectedLegacyCommit,
};
use faculties::mail::{self, BytesHandle, IntervalValue, TextHandle};
use faculties::schemas::mail::{
    self as schema, imported_legacy, IMPORT_DRAFT, IMPORT_RECEIVED, IMPORT_SENT,
};
use faculties::schemas::message::{local as legacy_read, KIND_READ_ID};
use faculties::storage::{load_signer, open_pile_strict};

/// Provenance of one native Mail migration commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailMigrationSource {
    /// Exact content, metadata, and resident closure of one legacy author.
    Authored(LegacyCommitCoordinate),
    /// Migration-authored canonical shadows over the complete verified head.
    /// Keeping this distinct avoids attributing a joined sibling value to
    /// either legacy author that only observed one side of it.
    Normalization {
        pin: LegacyPinCoordinate,
        head: CommitHandle,
    },
}

/// One self-contained native commit in the stopped-world migration plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailMigrationCommit {
    pub source: MailMigrationSource,
    pub fragment: Fragment,
}

/// Conservation and provenance census for one complete Mail migration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MailMigrationReport {
    pub authored_commits: usize,
    pub authored_empty_commits: usize,
    pub contentless_merges: usize,
    pub normalization_commits: usize,
    pub original_facts: usize,
    pub added_facts: usize,
    pub legacy_messages: usize,
    pub imported_received: usize,
    pub imported_sent: usize,
    pub imported_drafts: usize,
    pub legacy_reads: usize,
    pub canonical_reads: usize,
}

/// Pure stopped-world plan ready for native collection publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<MailMigrationCommit>,
    original: TribleSet,
    extras: TribleSet,
    report: MailMigrationReport,
}

impl MailMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[MailMigrationCommit] {
        &self.commits
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    pub fn added_facts(&self) -> &TribleSet {
        &self.extras
    }

    pub const fn report(&self) -> &MailMigrationReport {
        &self.report
    }

    pub fn materialized_facts(&self) -> TribleSet {
        self.commits
            .iter()
            .flat_map(|commit| commit.fragment.facts().iter().copied())
            .collect()
    }

    /// Recheck `output = old facts union extras` independently of publication.
    pub fn verify_conservation(&self) -> Result<()> {
        let mut expected = self.original.clone();
        expected += self.extras.clone();
        if self.materialized_facts() != expected {
            bail!("planned Mail collection is not exactly old facts union additive extras");
        }
        if self.extras.iter().any(|fact| self.original.contains(fact)) {
            bail!("Mail migration classifies an existing fact as an additive extra");
        }
        if self.report.authored_commits + self.report.normalization_commits != self.commits.len()
            || self.report.original_facts != self.original.len()
            || self.report.added_facts != self.extras.len()
        {
            bail!("Mail migration report disagrees with its planned commits");
        }
        Ok(())
    }
}

/// Plan the complete named legacy Mail branch without mutating its pile.
pub fn plan(source: &FrozenSource) -> Result<MailMigrationPlan> {
    let branch = source
        .legacy_branch(schema::LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Mail branch"))?;
    // Projection preserves parent-before-child order. Keep it: an interrupted
    // replay should reproduce the same causally meaningful prefix.
    let projected = project_legacy_authored_commits(source, &branch, validate_known_payloads)
        .context("project frozen Mail authored commits")?;
    plan_projected(&branch, projected, source.reader())
}

fn plan_projected(
    branch: &FrozenLegacyBranch,
    projected: Vec<ProjectedLegacyCommit>,
    reader: &PileReader,
) -> Result<MailMigrationPlan> {
    let source_pin = branch.pin_coordinate();
    let mut seen = BTreeSet::new();
    for commit in &projected {
        if commit.source.branch != source_pin.id || commit.source.pin != source_pin.value {
            bail!("Mail authored commits do not belong to one frozen branch pin");
        }
        if !seen.insert(commit.source) {
            bail!(
                "Mail migration input repeats legacy authored commit {}",
                hex::encode_upper(commit.source.commit.raw)
            );
        }
    }
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
    if seen != expected {
        bail!(
            "Mail authored commits do not exactly cover the frozen branch (expected {}, found {})",
            expected.len(),
            seen.len()
        );
    }

    let mut original = TribleSet::new();
    let mut by_source = BTreeMap::<LegacyCommitCoordinate, Fragment>::new();
    let mut metadata_by_source = BTreeMap::<LegacyCommitCoordinate, Fragment>::new();
    let mut authored_empty_commits = 0;
    for commit in projected {
        if commit.content.facts().is_empty() {
            authored_empty_commits += 1;
        }
        original += commit.content.facts().clone();
        by_source.insert(commit.source, commit.content);
        metadata_by_source.insert(commit.source, commit.metadata);
    }

    let ordered_sources: Vec<_> = branch
        .deltas
        .iter()
        .filter(|delta| delta.is_authored())
        .map(|delta| LegacyCommitCoordinate {
            branch: branch.branch,
            pin: branch.pin,
            commit: delta.commit,
        })
        .collect();
    let message_entities: BTreeSet<Id> = original
        .iter()
        .filter(|fact| fact.a() == &imported_legacy::message_id.id())
        .map(|fact| *fact.e())
        .collect();
    let read_entities: BTreeSet<Id> = find!(
        id: Id,
        pattern!(&original, [{ ?id @ metadata::tag: &KIND_READ_ID }])
    )
    .collect();
    if let Some(id) = message_entities.intersection(&read_entities).next() {
        bail!("legacy Mail entity {id:x} is both mail and a read receipt");
    }

    let mut report = MailMigrationReport {
        authored_commits: ordered_sources.len(),
        authored_empty_commits,
        contentless_merges: branch
            .deltas
            .iter()
            .filter(|delta| !delta.is_authored())
            .count(),
        original_facts: original.len(),
        legacy_messages: message_entities.len(),
        legacy_reads: read_entities.len(),
        ..MailMigrationReport::default()
    };
    let mut wires = BTreeMap::new();
    let mut normalization = Fragment::empty();

    for legacy_entity in &message_entities {
        let exact = entity_facts(&original, *legacy_entity);
        let record = mail::imported_payload(reader, &exact, *legacy_entity)
            .with_context(|| format!("validate legacy Mail entity {legacy_entity:x}"))?;
        match record.direction {
            IMPORT_RECEIVED => report.imported_received += 1,
            IMPORT_SENT => report.imported_sent += 1,
            IMPORT_DRAFT => report.imported_drafts += 1,
            _ => unreachable!("legacy payload validation admits exact directions"),
        }
        let message_id = read_text(reader, record.message_id)?;
        let raw = record
            .raw
            .map(|handle| read_bytes(reader, handle))
            .transpose()?;
        let payload = normalization.put::<SimpleArchive, _>(&exact);
        let publication = mail::imported_publication(
            *legacy_entity,
            record.direction,
            payload,
            &message_id,
            raw.as_deref(),
        )?;
        if !publication.files.facts().is_empty() {
            bail!("legacy Mail shadow unexpectedly emitted cross-collection Files facts");
        }
        wires.insert(*legacy_entity, publication.wire);
        normalization += publication.mail;
    }

    for read_entity in &read_entities {
        let exact = entity_facts(&original, *read_entity);
        let receipt = legacy_read_receipt(&exact, *read_entity)?;
        let wire = wires.get(&receipt.about).copied().ok_or_else(|| {
            anyhow!(
                "legacy Mail read receipt {read_entity:x} names missing mail {:x}",
                receipt.about
            )
        })?;
        let (mut canonical, canonical_id) = mail::read_observation_fragment(wire, receipt.reader);
        canonical += entity! { ExclusiveId::force_ref(&canonical_id) @
            legacy_read::read_at: receipt.read_at,
            metadata::created_at: receipt.created_at,
        };
        normalization += canonical;
    }

    let mut commits = Vec::with_capacity(ordered_sources.len());
    let mut materialized = TribleSet::new();
    for source in ordered_sources {
        let mut fragment = by_source
            .remove(&source)
            .expect("every authored source has one output partition");
        materialized += fragment.facts().clone();
        fragment.describe_with(
            metadata_by_source
                .remove(&source)
                .expect("every authored source has one metadata partition"),
        );
        // Parentage participates in the legacy commit identity but is not
        // semantic Mail content. Retain the exact coordinate in signed native
        // metadata so two otherwise-identical authored commits (especially
        // empty ones) cannot collapse into one CollectionCommit.
        fragment.describe_with(entity! {
            metadata::description: format!(
                "Mail legacy authored source branch {:X}, pin {}, commit {}",
                source.branch,
                hex::encode_upper(source.pin.raw),
                hex::encode_upper(source.commit.raw),
            )
        });
        commits.push(MailMigrationCommit {
            source: MailMigrationSource::Authored(source),
            fragment,
        });
    }
    if !by_source.is_empty() || !metadata_by_source.is_empty() {
        bail!("Mail planner produced output for an absent authored source");
    }
    let normalization_commits = usize::from(!normalization.facts().is_empty());
    if !normalization.facts().is_empty() {
        let head = branch
            .head
            .ok_or_else(|| anyhow!("legacy Mail normalization has no verified branch head"))?;
        normalization.describe_with(entity! {
            metadata::description: format!(
                "Mail migration normalization for legacy branch {:X}, pin {}, head {}",
                branch.branch,
                hex::encode_upper(branch.pin.raw),
                hex::encode_upper(head.raw),
            )
        });
        materialized += normalization.facts().clone();
        commits.push(MailMigrationCommit {
            source: MailMigrationSource::Normalization {
                pin: source_pin,
                head,
            },
            fragment: normalization,
        });
    }
    let extras = materialized.difference(&original);
    report.normalization_commits = normalization_commits;
    report.added_facts = extras.len();
    report.canonical_reads = materialized
        .iter()
        .filter(|fact| {
            fact.a() == &metadata::tag.id()
                && fact
                    .v::<inlineencodings::GenId>()
                    .try_from_inline::<Id>()
                    .is_ok_and(|kind| kind == schema::KIND_READ_OBSERVATION)
        })
        .count();

    let plan = MailMigrationPlan {
        source_pin,
        commits,
        original,
        extras,
        report,
    };
    plan.verify_conservation()?;

    let staged = plan
        .commits
        .iter()
        .fold(Fragment::empty(), |mut all, commit| {
            all += commit.fragment.clone();
            all
        });
    mail::validate_local_catalog_union(reader, &TribleSet::new(), &staged)
        .context("validate complete additive Mail migration")?;
    Ok(plan)
}

/// Publish a verified plan through the fixed native Mail collection.
///
/// The complete union is validated before the first append. Existing facts
/// need not be valid alone, so replay can finish after interruption on an
/// earlier plan prefix. Exact commit replay is content-addressed and
/// idempotent.
pub fn publish(
    source: &FrozenSource,
    plan: &MailMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Mail migration plan does not belong to this frozen source");
    }
    plan.verify_conservation()?;

    crate::write_authority::publish(target, key)
        .context("initialize WRITE authority before Mail migration publication")?;

    let signer = load_signer(target, key)?;
    let pile = open_pile_strict(target)?;
    let mut collection = faculties::collection_names::open(pile, schema::DEFAULT_SCOPE_ID, signer);
    let result = (|| {
        let existing = collection
            .materialize()
            .context("materialize existing native Mail value")?;
        let reader = collection
            .storage_mut()
            .reader()
            .context("open Mail publication attachment reader")?;
        let staged = plan
            .commits
            .iter()
            .fold(Fragment::empty(), |mut all, commit| {
                all += commit.fragment.clone();
                all
            });
        let expected = mail::validate_local_catalog_union(&reader, &existing, &staged)
            .context("preflight existing native value union legacy Mail plan")?;

        let mut published = Vec::with_capacity(plan.commits.len());
        for commit in &plan.commits {
            let source = match commit.source {
                MailMigrationSource::Authored(source) => format!(
                    "legacy authored commit {}",
                    hex::encode_upper(source.commit.raw)
                ),
                MailMigrationSource::Normalization { pin, head } => format!(
                    "legacy joined head {} at pin {}",
                    hex::encode_upper(head.raw),
                    hex::encode_upper(pin.value.raw)
                ),
            };
            published.push(
                collection
                    .commit(commit.fragment.clone())
                    .with_context(|| format!("publish Mail commit projected from {source}"))?,
            );
        }
        let actual = collection
            .materialize()
            .context("rematerialize published Mail migration")?;
        if actual != expected {
            bail!("published Mail materialization differs from its exact preflight candidate");
        }
        Ok(published)
    })();
    finish_pile(collection.into_storage(), result)
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close();
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(anyhow!("close Mail target pile: {error}")),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Mail target pile also failed: {close_error}"
        ))),
    }
}

#[derive(Clone, Copy, Debug)]
struct LegacyReadReceipt {
    about: Id,
    reader: Id,
    read_at: IntervalValue,
    created_at: IntervalValue,
}

fn legacy_read_receipt(facts: &TribleSet, id: Id) -> Result<LegacyReadReceipt> {
    let tags: BTreeSet<Id> =
        find!(tag: Id, pattern!(facts, [{ id @ metadata::tag: ?tag }])).collect();
    if tags != BTreeSet::from([KIND_READ_ID]) {
        bail!("legacy Mail read receipt {id:x} has an invalid kind set");
    }
    let receipt = LegacyReadReceipt {
        about: exactly_one(
            find!(v: Id, pattern!(facts, [{ id @ legacy_read::about_message: ?v }])).collect(),
            "legacy read subject",
        )?,
        reader: exactly_one(
            find!(v: Id, pattern!(facts, [{ id @ legacy_read::reader: ?v }])).collect(),
            "legacy read reader",
        )?,
        read_at: exactly_one(
            find!(v: IntervalValue, pattern!(facts, [{ id @ legacy_read::read_at: ?v }])).collect(),
            "legacy read time",
        )?,
        created_at: exactly_one(
            find!(v: IntervalValue, pattern!(facts, [{ id @ metadata::created_at: ?v }])).collect(),
            "legacy read creation time",
        )?,
    };
    validate_point(receipt.read_at, "legacy read time")?;
    validate_point(receipt.created_at, "legacy read creation time")?;
    let exact = entity! { ExclusiveId::force_ref(&id) @
        metadata::tag: &KIND_READ_ID,
        legacy_read::about_message: &receipt.about,
        legacy_read::reader: &receipt.reader,
        legacy_read::read_at: receipt.read_at,
        metadata::created_at: receipt.created_at,
    };
    if exact.facts() != facts {
        bail!("legacy Mail read receipt {id:x} is not an exact supported record");
    }
    Ok(receipt)
}

fn validate_known_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    let text_attributes = BTreeSet::from([
        imported_legacy::subject.id(),
        imported_legacy::body.id(),
        imported_legacy::message_id.id(),
        metadata::name.id(),
    ]);
    for fact in facts {
        if text_attributes.contains(fact.a()) {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::UTF8String>>();
            let _: View<str> = reader
                .get(handle)
                .with_context(|| format!("read legacy Mail text {}", hex::encode(handle.raw)))?;
        } else if fact.a() == &imported_legacy::raw.id() {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::RawBytes>>();
            let _: anybytes::Bytes = reader
                .get(handle)
                .with_context(|| format!("read legacy Mail bytes {}", hex::encode(handle.raw)))?;
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

fn exactly_one<T: Ord>(mut values: BTreeSet<T>, label: &str) -> Result<T> {
    match values.len() {
        1 => Ok(values.pop_first().expect("one value")),
        count => bail!("{label} has {count} distinct values; expected exactly one"),
    }
}

fn validate_point(value: IntervalValue, label: &str) -> Result<()> {
    let (low, high): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode {label}: {error:?}"))?;
    if low != high {
        bail!("{label} must be a point interval");
    }
    Ok(())
}

fn read_text(reader: &PileReader, handle: TextHandle) -> Result<String> {
    let value: View<str> = reader
        .get(handle)
        .with_context(|| format!("read legacy Mail text {}", hex::encode(handle.raw)))?;
    Ok(value.to_string())
}

fn read_bytes(reader: &PileReader, handle: BytesHandle) -> Result<Vec<u8>> {
    let value: anybytes::Bytes = reader
        .get(handle)
        .with_context(|| format!("read legacy Mail bytes {}", hex::encode(handle.raw)))?;
    Ok(value.as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use triblespace::core::repo::BlobStoreList;

    use super::*;
    use crate::collection_cutover::test_support::{TestBranchSpec, TestDeltaSpec, TestSourceSpec};
    use faculties::storage::{initialize_signer, publish_fragment};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-mail-cutover-{}-{serial}",
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
        source: FrozenSource,
        target: std::path::PathBuf,
        key: std::path::PathBuf,
        source_facts: TribleSet,
    }

    fn at(second: u8) -> IntervalValue {
        let epoch = Epoch::from_gregorian_utc(2026, 8, 10, 0, 0, second, 0);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn legacy_message(message_id: &str) -> (Fragment, Id) {
        let raw = format!(
            "From: Alice <alice@example.test>\r\nTo: jp@example.test\r\nMessage-ID: <{message_id}>\r\nDate: Mon, 10 Aug 2026 00:00:01 +0000\r\nSubject: Legacy\r\n\r\nbody"
        );
        let mut fragment = Fragment::empty();
        let message_id_handle = fragment.put::<blobencodings::UTF8String, _>(message_id.to_owned());
        let subject = fragment.put::<blobencodings::UTF8String, _>("Legacy".to_owned());
        let body = fragment.put::<blobencodings::UTF8String, _>("body".to_owned());
        let raw = fragment.put::<blobencodings::RawBytes, _>(raw.into_bytes());
        let id = entity! { imported_legacy::message_id: message_id_handle }
            .root()
            .unwrap();
        fragment += entity! { ExclusiveId::force_ref(&id) @
            metadata::tag: &schema::LEGACY_KIND_MESSAGE,
            metadata::created_at: at(1),
            imported_legacy::subject: subject,
            imported_legacy::body: body,
            imported_legacy::message_id: message_id_handle,
            imported_legacy::sent_at: at(1),
            imported_legacy::raw: raw,
        };
        (fragment, id)
    }

    fn fixture() -> Fixture {
        let directory = TestDirectory::new();
        let source = directory.0.join("source.pile");
        let target = directory.0.join("target.pile");
        let key = directory.0.join("target.key");
        File::create(&source).unwrap();
        File::create(&target).unwrap();
        let (message, message_id) = legacy_message("legacy@example.test");
        let message_facts = message.facts().clone();
        let read_id = Id::new([0x44; 16]).unwrap();
        let read = entity! { ExclusiveId::force_ref(&read_id) @
            metadata::tag: &KIND_READ_ID,
            legacy_read::about_message: &message_id,
            legacy_read::reader: &Id::new([0x45; 16]).unwrap(),
            legacy_read::read_at: at(2),
            metadata::created_at: at(2),
        };
        let read_facts = read.facts().clone();
        initialize_signer(&target, Some(&key)).unwrap();
        crate::write_authority::publish(&target, Some(&key)).unwrap();
        let source = TestSourceSpec::new(vec![TestBranchSpec::new(
            schema::LEGACY_BRANCH_NAME,
            Id::new([0x61; 16]).unwrap(),
            SigningKey::from_bytes(&[0x61; 32]),
            vec![
                TestDeltaSpec::authored(message, "legacy message"),
                TestDeltaSpec::authored(read, "legacy read"),
                TestDeltaSpec::authored(Fragment::empty(), "authored empty"),
                TestDeltaSpec::authored(Fragment::empty(), "authored empty"),
            ],
        )])
        .freeze(&source)
        .unwrap()
        .source;

        let mut source_facts = message_facts;
        source_facts += read_facts;
        Fixture {
            _directory: directory,
            source,
            target,
            key,
            source_facts,
        }
    }

    fn split_merge_fixture() -> Fixture {
        let directory = TestDirectory::new();
        let source = directory.0.join("split-source.pile");
        let target = directory.0.join("split-target.pile");
        let key = directory.0.join("split-target.key");
        File::create(&source).unwrap();
        File::create(&target).unwrap();
        let (message, _) = legacy_message("joined@example.test");
        let (_, facts, _, blobs) = message.into_parts();
        let left_facts: TribleSet = facts
            .iter()
            .filter(|fact| {
                [
                    metadata::tag.id(),
                    imported_legacy::message_id.id(),
                    imported_legacy::subject.id(),
                    imported_legacy::body.id(),
                ]
                .contains(fact.a())
            })
            .copied()
            .collect();
        let right_facts = facts.difference(&left_facts);
        assert!(!left_facts.is_empty());
        assert!(!right_facts.is_empty());
        initialize_signer(&target, Some(&key)).unwrap();
        crate::write_authority::publish(&target, Some(&key)).unwrap();
        let source = TestSourceSpec::new(vec![TestBranchSpec::new(
            schema::LEGACY_BRANCH_NAME,
            Id::new([0x62; 16]).unwrap(),
            SigningKey::from_bytes(&[0x62; 32]),
            vec![
                TestDeltaSpec::authored(
                    Fragment::from_facts_and_blobs(left_facts, blobs.clone()),
                    "legacy left half",
                ),
                TestDeltaSpec::authored(
                    Fragment::from_facts_and_blobs(right_facts, blobs),
                    "legacy right half",
                )
                .with_parents([]),
                TestDeltaSpec::merge([0, 1]),
            ],
        )])
        .freeze(&source)
        .unwrap()
        .source;

        Fixture {
            _directory: directory,
            source,
            target,
            key,
            source_facts: facts,
        }
    }

    fn materialize(path: &Path, key: &Path) -> TribleSet {
        let signer = load_signer(path, Some(key)).unwrap();
        let pile = open_pile_strict(path).unwrap();
        let mut collection =
            faculties::collection_names::open(pile, schema::DEFAULT_SCOPE_ID, signer);
        let facts = collection.materialize().unwrap();
        collection.into_storage().close().unwrap();
        facts
    }

    #[test]
    fn plan_is_strictly_additive_and_preserves_authored_empty_commits() {
        let fixture = fixture();
        let source = &fixture.source;
        let plan = plan(source).unwrap();
        plan.verify_conservation().unwrap();
        assert_eq!(plan.original_facts(), &fixture.source_facts);
        assert_eq!(plan.report().authored_commits, 4);
        assert_eq!(plan.report().authored_empty_commits, 2);
        assert_eq!(plan.report().normalization_commits, 1);
        assert_eq!(plan.report().legacy_messages, 1);
        assert_eq!(plan.report().canonical_reads, 1);
        assert!(!plan.added_facts().is_empty());

        let branch = source
            .legacy_branch(schema::LEGACY_BRANCH_NAME)
            .unwrap()
            .unwrap();
        let projected =
            project_legacy_authored_commits(source, &branch, validate_known_payloads).unwrap();
        for expected in projected {
            let actual = plan
                .commits()
                .iter()
                .find(|commit| commit.source == MailMigrationSource::Authored(expected.source))
                .unwrap();
            assert!(expected
                .content
                .facts()
                .iter()
                .all(|fact| actual.fragment.facts().contains(fact)));

            let mut expected_metafacts = expected.content.metafacts().clone();
            expected_metafacts += expected.metadata.facts().clone();
            expected_metafacts += expected.metadata.metafacts().clone();
            assert!(expected_metafacts
                .iter()
                .all(|fact| actual.fragment.metafacts().contains(fact)));

            let mut expected_blobs = expected.content.blobs().clone();
            expected_blobs.union(expected.metadata.blobs().clone());
            let mut actual_blob_store = actual.fragment.blobs().clone();
            let actual_blobs = actual_blob_store.reader().unwrap();
            for (handle, _) in expected_blobs.reader().unwrap().iter() {
                assert!(actual_blobs.contains_blob(handle).unwrap());
            }
        }
        assert!(plan.commits().iter().any(|commit| {
            commit.fragment.facts().is_empty() && !commit.fragment.metafacts().is_empty()
        }));
    }

    #[test]
    fn sibling_authors_join_through_a_distinct_normalization_commit() {
        let fixture = split_merge_fixture();
        let source = &fixture.source;
        let branch = source
            .legacy_branch(schema::LEGACY_BRANCH_NAME)
            .unwrap()
            .unwrap();
        let head = branch.head.unwrap();
        let plan = plan(source).unwrap();

        assert_eq!(plan.original_facts(), &fixture.source_facts);
        assert_eq!(plan.report().authored_commits, 2);
        assert_eq!(plan.report().contentless_merges, 1);
        assert_eq!(plan.report().normalization_commits, 1);
        assert!(plan.commits().iter().any(|commit| {
            commit.source
                == MailMigrationSource::Normalization {
                    pin: branch.pin_coordinate(),
                    head,
                }
        }));
        plan.verify_conservation().unwrap();

        publish(source, &plan, &fixture.target, Some(&fixture.key)).unwrap();
        assert_eq!(
            materialize(&fixture.target, &fixture.key),
            plan.materialized_facts()
        );
    }

    #[test]
    fn publication_is_idempotent_and_conserves_the_exact_candidate() {
        let fixture = fixture();
        let source = &fixture.source;
        let plan = plan(source).unwrap();
        let published = publish(source, &plan, &fixture.target, Some(&fixture.key)).unwrap();
        assert_eq!(published.len(), plan.commits().len());
        assert_eq!(
            published
                .iter()
                .map(CollectionCommit::id)
                .collect::<BTreeSet<_>>()
                .len(),
            published.len(),
            "distinct legacy authored coordinates must not collapse"
        );
        let length = fs::metadata(&fixture.target).unwrap().len();
        publish(source, &plan, &fixture.target, Some(&fixture.key)).unwrap();
        assert_eq!(fs::metadata(&fixture.target).unwrap().len(), length);
        assert_eq!(
            materialize(&fixture.target, &fixture.key),
            plan.materialized_facts()
        );
    }

    #[test]
    fn interrupted_prefix_replay_converges() {
        let fixture = fixture();
        let source = &fixture.source;
        let plan = plan(source).unwrap();
        publish_fragment(
            &fixture.target,
            Some(&fixture.key),
            schema::DEFAULT_SCOPE_ID,
            plan.commits()[0].fragment.clone(),
        )
        .unwrap();
        publish(source, &plan, &fixture.target, Some(&fixture.key)).unwrap();
        assert_eq!(
            materialize(&fixture.target, &fixture.key),
            plan.materialized_facts()
        );
    }

    #[test]
    fn preflight_conflict_appends_nothing() {
        let fixture = fixture();
        let source = &fixture.source;
        let plan = plan(source).unwrap();
        let malformed = entity! { metadata::tag: &schema::KIND_WIRE_MESSAGE };
        publish_fragment(
            &fixture.target,
            Some(&fixture.key),
            schema::DEFAULT_SCOPE_ID,
            malformed,
        )
        .unwrap();
        let length = fs::metadata(&fixture.target).unwrap().len();
        assert!(publish(source, &plan, &fixture.target, Some(&fixture.key)).is_err());
        assert_eq!(fs::metadata(&fixture.target).unwrap().len(), length);
    }
}
