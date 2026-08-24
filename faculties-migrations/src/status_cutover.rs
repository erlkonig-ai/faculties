//! Strictly additive stopped-world projection of legacy Status events.
//!
//! The historical writer minted a random entity for every immutable event.
//! The native writer derives the event id from `(window, text, timestamp)`.
//! This transform validates the complete frozen catalog and republishes every
//! authored fragment byte-for-byte. It additionally reconstructs intrinsic
//! shadow records, collapses exact duplicate tuples with set semantics, and
//! attributes each shadow to the earliest authored commit that contained one
//! of its legacy text facts. Native readers select the intrinsic records; the
//! original random-id facts stay present as inert provenance. Contentless
//! repository merges remain ancestry only; authored empty or duplicate
//! commits remain metadata-carrying native commits. The old branch pin is
//! never changed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::prelude::*;

use crate::collection_cutover::{
    project_legacy_authored_commits, FrozenSource, LegacyCommitCoordinate, LegacyPinCoordinate,
};
use faculties::schemas::status::{
    status as status_attr, DEFAULT_SCOPE_ID, KIND_STATUS_UPDATE, STATUS_BRANCH_NAME,
};
use faculties::status::{self, StatusRow};
use faculties::storage::publish_fragments;

/// One native commit projected from one exact authored legacy commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
}

/// Conservation and normalization summary for a complete migration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StatusMigrationReport {
    pub authored_commits: usize,
    pub legacy_events: usize,
    pub preserved_facts: usize,
    pub canonical_events: usize,
    pub canonical_facts: usize,
    pub output_facts: usize,
}

/// Pure stopped-world plan ready for native collection publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<StatusMigrationCommit>,
    original: TribleSet,
    canonical: TribleSet,
    report: StatusMigrationReport,
}

impl StatusMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[StatusMigrationCommit] {
        &self.commits
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    pub fn canonical_facts(&self) -> &TribleSet {
        &self.canonical
    }

    pub const fn report(&self) -> &StatusMigrationReport {
        &self.report
    }

    pub fn materialized_facts(&self) -> TribleSet {
        let mut facts = TribleSet::new();
        for commit in &self.commits {
            facts += commit.fragment.facts().clone();
        }
        facts
    }

    pub fn verify_conservation(&self) -> Result<()> {
        let mut expected = self.original.clone();
        expected += self.canonical.clone();
        if self.materialized_facts() != expected {
            bail!("planned Status collection is not original facts union canonical shadows");
        }
        Ok(())
    }

    fn validate(&self, reader: &PileReader) -> Result<()> {
        self.verify_conservation()?;
        let mut complete = Fragment::empty();
        for commit in &self.commits {
            complete += commit.fragment.clone();
        }
        let validated = status::validate_catalog_union(reader, &TribleSet::new(), &complete)
            .context("validate planned Status collection and attachments")?;
        if validated != self.materialized_facts() {
            bail!("planned Status fragment union changed during validation");
        }
        Ok(())
    }
}

/// Plan the complete named legacy Status branch without mutating its pile.
pub fn plan(source: &FrozenSource) -> Result<StatusMigrationPlan> {
    let branch = source
        .legacy_branch(STATUS_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Status branch"))?;
    let mut projected = project_legacy_authored_commits(source, &branch, validate_legacy_payloads)
        .context("project frozen Status authored commits")?;
    projected.sort_unstable_by_key(|commit| commit.source);

    for pair in projected.windows(2) {
        if pair[0].source == pair[1].source {
            bail!(
                "Status migration input repeats legacy authored commit {}",
                hex::encode_upper(pair[0].source.commit.raw)
            );
        }
    }

    let source_pin = branch.pin_coordinate();
    let mut original = TribleSet::new();
    let mut text_witnesses = BTreeMap::<Id, BTreeSet<LegacyCommitCoordinate>>::new();
    for commit in &projected {
        if commit.source.branch != source_pin.id || commit.source.pin != source_pin.value {
            bail!("Status authored commits do not belong to one frozen branch pin");
        }
        original += commit.content.facts().clone();
        for fact in commit
            .content
            .facts()
            .iter()
            .filter(|fact| fact.a() == &status_attr::text.id())
        {
            text_witnesses
                .entry(*fact.e())
                .or_default()
                .insert(commit.source);
        }
    }

    let legacy_rows = validate_legacy_catalog(source.reader(), &original)?;

    // First group by the resulting intrinsic id. Two different historical
    // random ids may denote the same tuple; assigning before this grouping
    // would duplicate one assertion across native commits instead of applying
    // set semantics.
    let mut canonical_records = BTreeMap::<Id, (Fragment, LegacyCommitCoordinate)>::new();
    for row in &legacy_rows {
        let owner = text_witnesses
            .get(&row.event)
            .and_then(|witnesses| witnesses.iter().next())
            .copied()
            .ok_or_else(|| {
                anyhow!(
                    "legacy Status event {:X} has no authored text witness",
                    row.event
                )
            })?;
        let record = status::status_record(row.window, row.text, row.at);
        let intrinsic = record.root().expect("canonical Status record has a root");
        match canonical_records.entry(intrinsic) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((record, owner));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if entry.get().0.facts() != record.facts() {
                    bail!("intrinsic Status id collision at {intrinsic:X}");
                }
                if owner < entry.get().1 {
                    entry.get_mut().1 = owner;
                }
            }
        }
    }

    let mut canonical = TribleSet::new();
    let mut content_by_source = BTreeMap::<LegacyCommitCoordinate, Fragment>::new();
    for (_, (record, owner)) in canonical_records {
        canonical += record.facts().clone();
        *content_by_source
            .entry(owner)
            .or_insert_with(Fragment::empty) += record;
    }

    let mut commits = Vec::with_capacity(projected.len());
    for projected in projected {
        // Preserve the authored content exactly. Canonical records are extras,
        // never replacements; this keeps every old entity id and fact while
        // allowing the native intrinsic projection to ignore them.
        let mut content = projected.content;
        if let Some(shadows) = content_by_source.remove(&projected.source) {
            content += shadows;
        }
        content.describe_with(projected.metadata);
        commits.push(StatusMigrationCommit {
            source: projected.source,
            fragment: content,
        });
    }
    if !content_by_source.is_empty() {
        bail!("canonical Status partition names a non-input source coordinate");
    }

    let mut output = TribleSet::new();
    for commit in &commits {
        output += commit.fragment.facts().clone();
    }
    let plan = StatusMigrationPlan {
        source_pin,
        report: StatusMigrationReport {
            authored_commits: commits.len(),
            legacy_events: legacy_rows.len(),
            preserved_facts: original.len(),
            canonical_events: canonical.len() / 4,
            canonical_facts: canonical.len(),
            output_facts: output.len(),
        },
        commits,
        original,
        canonical,
    };
    plan.validate(source.reader())?;
    Ok(plan)
}

/// Publish a verified plan through the native collection facade.
///
/// Every legacy Status writer must remain stopped from [`FrozenSource`]
/// creation through publication. Replay is exact and idempotent.
pub fn publish(
    source: &FrozenSource,
    plan: &StatusMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Status migration plan does not belong to this frozen source");
    }
    plan.validate(source.reader())?;
    publish_fragments(
        target,
        key,
        DEFAULT_SCOPE_ID,
        plan.commits.iter().map(|commit| commit.fragment.clone()),
    )
}

fn validate_legacy_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts
        .iter()
        .filter(|fact| fact.a() == &status_attr::text.id())
    {
        status::read_text(reader, *fact.v())
            .with_context(|| format!("read legacy Status text on event {:X}", fact.e()))?;
    }
    Ok(())
}

fn validate_legacy_catalog(reader: &PileReader, facts: &TribleSet) -> Result<Vec<StatusRow>> {
    let rows = status::load_tagged_status_rows(facts)?;
    let mut fact_counts = BTreeMap::<Id, usize>::new();
    for fact in facts {
        *fact_counts.entry(*fact.e()).or_default() += 1;
    }

    for row in &rows {
        status::point_timestamp(row.at)
            .with_context(|| format!("validate legacy Status event {:X}", row.event))?;
        status::read_text(reader, row.text)
            .with_context(|| format!("validate text on legacy Status event {:X}", row.event))?;
        let count = fact_counts.get(&row.event).copied().unwrap_or_default();
        if count != 4 {
            bail!(
                "legacy Status event {:X} has {count} facts; expected exactly four",
                row.event
            );
        }
        if !exists!(pattern!(facts, [{ row.event @ metadata::tag: &KIND_STATUS_UPDATE }]))
            || !exists!(pattern!(facts, [{ row.event @ status_attr::window: row.window }]))
            || !exists!(pattern!(facts, [{ row.event @ status_attr::text: row.text }]))
            || !exists!(pattern!(facts, [{ row.event @ metadata::created_at: row.at }]))
        {
            bail!(
                "legacy Status event {:X} is not the exact four-field record",
                row.event
            );
        }
    }

    if rows.len() * 4 != facts.len() {
        bail!(
            "legacy Status catalog has {} facts outside complete events",
            facts.len().saturating_sub(rows.len() * 4)
        );
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use triblespace::core::repo::BlobStore;

    use super::*;
    use crate::collection_cutover::test_support::{TestBranchSpec, TestDeltaSpec, TestSourceSpec};
    use faculties::storage::{initialize_signer, load_signer, open_pile_strict};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-status-cutover-{}-{serial}",
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
        window: Id,
        frozen: FrozenSource,
    }

    fn at(seconds: f64) -> status::IntervalValue {
        let epoch = Epoch::from_unix_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn legacy_event(window: Id, text: &str, at: status::IntervalValue) -> Fragment {
        let mut fragment = Fragment::empty();
        let text = fragment.put::<blobencodings::UTF8String, _>(text.to_owned());
        fragment += entity! { &ufoid() @
            metadata::tag: &KIND_STATUS_UPDATE,
            status_attr::window: window,
            status_attr::text: text,
            metadata::created_at: at,
        };
        fragment
    }

    fn fixture() -> Fixture {
        let directory = TestDirectory::new();
        let pile = directory.0.join("status.pile");
        let key = directory.0.join("status.key");
        File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        let window = Id::new([0x72; 16]).unwrap();
        let frozen = TestSourceSpec::new(vec![TestBranchSpec::new(
            STATUS_BRANCH_NAME,
            Id::new([0x71; 16]).unwrap(),
            SigningKey::from_bytes(&[0x71; 32]),
            vec![
                TestDeltaSpec::authored(legacy_event(window, "same", at(1.0)), "first"),
                TestDeltaSpec::authored(legacy_event(window, "same", at(1.0)), "duplicate tuple"),
                TestDeltaSpec::authored(Fragment::empty(), "authored empty"),
                TestDeltaSpec::authored(legacy_event(window, "later", at(2.0)), "later"),
            ],
        )])
        .freeze(&pile)
        .unwrap()
        .source;
        Fixture {
            _directory: directory,
            pile,
            key,
            window,
            frozen,
        }
    }

    #[test]
    fn plan_reconstructs_intrinsic_events_and_collapses_duplicate_tuples() {
        let fixture = fixture();
        let plan = plan(&fixture.frozen).unwrap();

        assert_eq!(plan.report().authored_commits, 4);
        assert_eq!(plan.report().legacy_events, 3);
        assert_eq!(plan.report().preserved_facts, 12);
        assert_eq!(plan.report().canonical_events, 2);
        assert_eq!(plan.report().canonical_facts, 8);
        assert_eq!(plan.report().output_facts, 20);
        plan.verify_conservation().unwrap();
        let mut expected = plan.original_facts().clone();
        expected += plan.canonical_facts().clone();
        assert_eq!(plan.materialized_facts(), expected);
        assert_ne!(plan.materialized_facts(), plan.canonical_facts().clone());
        status::validate_catalog_union(
            fixture.frozen.reader(),
            &TribleSet::new(),
            &plan
                .commits()
                .iter()
                .fold(Fragment::empty(), |mut all, commit| {
                    all += commit.fragment.clone();
                    all
                }),
        )
        .unwrap();

        let rows = status::load_status_rows(plan.canonical_facts()).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.window == fixture.window));
        // The three random legacy identities survive exactly, but only the
        // two intrinsic shadows participate in the native Status view.
        assert_eq!(
            status::load_tagged_status_rows(plan.original_facts())
                .unwrap()
                .len(),
            3
        );
        assert!(status::load_status_rows(plan.original_facts())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn publication_is_idempotent_and_preserves_text() {
        let fixture = fixture();
        let plan = plan(&fixture.frozen).unwrap();

        let first = publish(&fixture.frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        let length = fs::metadata(&fixture.pile).unwrap().len();
        let second = publish(&fixture.frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(first, second);
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), length);

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection = faculties::collection_names::open(pile, DEFAULT_SCOPE_ID, signer);
        let facts = collection.materialize().unwrap();
        let reader = collection.storage_mut().reader().unwrap();
        status::validate_catalog(&reader, &facts).unwrap();
        let texts: BTreeSet<String> = status::load_status_rows(&facts)
            .unwrap()
            .into_iter()
            .map(|row| status::read_text(&reader, row.text).unwrap())
            .collect();
        assert_eq!(
            texts,
            BTreeSet::from(["later".to_owned(), "same".to_owned()])
        );
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn malformed_legacy_catalog_fails_before_native_publication() {
        let directory = TestDirectory::new();
        let pile = directory.0.join("broken.pile");
        File::create(&pile).unwrap();
        let frozen = TestSourceSpec::new(vec![TestBranchSpec::new(
            STATUS_BRANCH_NAME,
            Id::new([0x73; 16]).unwrap(),
            SigningKey::from_bytes(&[0x73; 32]),
            vec![TestDeltaSpec::authored(
                entity! { &ufoid() @ metadata::tag: &KIND_STATUS_UPDATE },
                "malformed",
            )],
        )])
        .freeze(&pile)
        .unwrap();
        let error = plan(&frozen.source).unwrap_err();
        assert!(format!("{error:#}").contains("Status event"));
    }
}
