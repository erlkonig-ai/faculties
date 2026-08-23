//! Exact stopped-world migration of the legacy Atlas metadata branch.
//!
//! Atlas metadata is already monotone evidence: the storage cutover changes
//! no entity, fact, or semantic commit metadata. Every authored Repository
//! commit becomes one independently signed collection commit; authored empty
//! commits remain commits, while contentless merge nodes remain verified
//! ancestry only. The legacy pin is never changed or removed.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::collection::CollectionCommit;
use triblespace::core::repo::pile::PileReader;
use triblespace::prelude::*;

use crate::collection_cutover::{
    project_legacy_authored_commits, FrozenSource, LegacyCommitCoordinate, LegacyPinCoordinate,
};
use crate::write_authority::publish_fragments;
use faculties::schemas::atlas::DEFAULT_SCOPE_ID;

pub use faculties::schemas::atlas::LEGACY_BRANCH_NAME;

/// One native commit projected from one verified legacy authored commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtlasMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
}

/// Conservation summary for one complete Atlas migration plan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AtlasMigrationReport {
    pub authored_commits: usize,
    pub authored_empty_commits: usize,
    pub contentless_merges: usize,
    pub facts: usize,
}

/// Pure stopped-world plan ready for native collection publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtlasMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<AtlasMigrationCommit>,
    original: TribleSet,
    report: AtlasMigrationReport,
}

impl AtlasMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[AtlasMigrationCommit] {
        &self.commits
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    pub const fn report(&self) -> &AtlasMigrationReport {
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
            bail!("planned Atlas collection does not exactly preserve legacy facts");
        }
        if self.report.authored_commits != self.commits.len()
            || self.report.facts != self.original.len()
        {
            bail!("Atlas migration report disagrees with its planned commits");
        }
        Ok(())
    }
}

/// Plan the complete named legacy Atlas branch without mutating its pile.
pub fn plan(source: &FrozenSource) -> Result<AtlasMigrationPlan> {
    let branch = source
        .legacy_branch(LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Atlas branch"))?;
    let contentless_merges = branch
        .deltas
        .iter()
        .filter(|delta| !delta.is_authored())
        .count();
    // The projector returns deterministic parent-before-child order. Keeping
    // it makes every interrupted publication prefix a meaningful prefix of
    // the verified source history rather than an arbitrary hash ordering.
    let projected = project_legacy_authored_commits(source, &branch, validate_known_payloads)
        .context("project frozen Atlas authored commits")?;
    let mut seen = BTreeSet::new();
    for commit in &projected {
        if !seen.insert(commit.source) {
            bail!(
                "Atlas migration input repeats legacy authored commit {}",
                hex::encode_upper(commit.source.commit.raw)
            );
        }
    }

    let source_pin = branch.pin_coordinate();
    let mut original = TribleSet::new();
    let mut authored_empty_commits = 0;
    let mut commits = Vec::with_capacity(projected.len());
    for projected in projected {
        if projected.source.branch != source_pin.id || projected.source.pin != source_pin.value {
            bail!("Atlas authored commits do not belong to one frozen branch pin");
        }
        if projected.content.facts().is_empty() {
            authored_empty_commits += 1;
        }
        original += projected.content.facts().clone();
        let mut fragment = projected.content;
        fragment.describe_with(projected.metadata);
        commits.push(AtlasMigrationCommit {
            source: projected.source,
            fragment,
        });
    }

    let plan = AtlasMigrationPlan {
        source_pin,
        report: AtlasMigrationReport {
            authored_commits: commits.len(),
            authored_empty_commits,
            contentless_merges,
            facts: original.len(),
        },
        commits,
        original,
    };
    plan.verify_conservation()?;
    Ok(plan)
}

/// Publish a verified Atlas plan into the one fixed native collection.
///
/// Every legacy Atlas writer must remain stopped from source freeze through
/// final verification. Exact replay is content-addressed and idempotent.
pub fn publish(
    source: &FrozenSource,
    plan: &AtlasMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Atlas migration plan does not belong to this frozen source");
    }
    plan.verify_conservation()?;
    publish_fragments(
        target,
        key,
        DEFAULT_SCOPE_ID,
        plan.commits.iter().map(|commit| commit.fragment.clone()),
    )
}

/// Strictly load every direct, schema-known Atlas attachment.
///
/// The generic projector additionally copies the complete resident closure,
/// so unknown future attributes remain preserved rather than filtered out.
pub fn validate_known_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    faculties::atlas::validate_known_payloads(reader, facts)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace::core::metadata;
    use triblespace::core::repo::BlobStoreGet;

    use super::*;
    use crate::collection_cutover::test_support::{TestBranchSpec, TestDeltaSpec, TestSourceSpec};
    use faculties::storage::{initialize_signer, load_signer, open_pile_strict};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-atlas-cutover-{}-{serial}",
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
        pile: std::path::PathBuf,
        key: std::path::PathBuf,
        source_facts: TribleSet,
        source: FrozenSource,
    }

    fn atlas_fragment(entity: Id, label: &str) -> Fragment {
        let mut fragment = Fragment::empty();
        let name = fragment.put::<blobencodings::UTF8String, _>(label.to_owned());
        let description =
            fragment.put::<blobencodings::UTF8String, _>(format!("Description for {label}"));
        let formatter = fragment.put::<blobencodings::WasmCode, _>(vec![0, 97, 115, 109]);
        fragment += entity! { ExclusiveId::force_ref(&entity) @
            metadata::name: name,
            metadata::description: description,
            metadata::value_formatter: formatter,
            metadata::tag: &metadata::KIND_ATTRIBUTE_USAGE,
        };
        fragment
    }

    fn fixture() -> Fixture {
        let directory = TestDirectory::new();
        let pile = directory.0.join("atlas.pile");
        let key = directory.0.join("atlas.key");
        File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        let first = atlas_fragment(Id::new([0x31; 16]).unwrap(), "first attribute");
        let second = atlas_fragment(Id::new([0x32; 16]).unwrap(), "second attribute");
        let mut source_facts = first.facts().clone();
        source_facts += second.facts().clone();
        // Sibling authored commits force one contentless merge. One sibling is
        // intentionally empty so its semantic metadata still has to survive.
        let source = TestSourceSpec::new(vec![TestBranchSpec::new(
            LEGACY_BRANCH_NAME,
            Id::new([0x71; 16]).unwrap(),
            SigningKey::from_bytes(&[0x71; 32]),
            vec![
                TestDeltaSpec::authored(first, "first schema")
                    .with_metadata(entity! { metadata::description: "legacy Atlas provenance" }),
                TestDeltaSpec::authored(second, "second schema"),
                TestDeltaSpec::authored(Fragment::empty(), "authored empty").with_parents([0]),
                TestDeltaSpec::merge([1, 2]),
            ],
        )])
        .freeze(&pile)
        .unwrap()
        .source;
        Fixture {
            _directory: directory,
            pile,
            key,
            source_facts,
            source,
        }
    }

    #[test]
    fn plan_is_exact_and_preserves_empty_authorship_and_merge_ancestry() {
        let fixture = fixture();
        let plan = plan(&fixture.source).unwrap();

        plan.verify_conservation().unwrap();
        assert_eq!(plan.original_facts(), &fixture.source_facts);
        assert_eq!(plan.report().authored_commits, 3);
        assert_eq!(plan.report().authored_empty_commits, 1);
        assert_eq!(plan.report().contentless_merges, 1);
        assert!(plan.commits().iter().any(|commit| {
            commit.fragment.facts().is_empty() && !commit.fragment.metafacts().is_empty()
        }));
    }

    #[test]
    fn publication_is_idempotent() {
        let fixture = fixture();
        let plan = plan(&fixture.source).unwrap();

        let first = publish(&fixture.source, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        let first_length = fs::metadata(&fixture.pile).unwrap().len();
        let second = publish(&fixture.source, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(first, second);
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), first_length);

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection = faculties::collection_names::open(pile, DEFAULT_SCOPE_ID, signer);
        assert_eq!(collection.materialize().unwrap(), fixture.source_facts);
        let reader = collection.storage_mut().reader().unwrap();
        for (actual, expected) in first.iter().zip(plan.commits()) {
            let data: TribleSet = reader
                .get(inlineencodings::Handle::<SimpleArchive>::from_hash(
                    actual.data(),
                ))
                .unwrap();
            let metadata: TribleSet = reader.get(actual.metadata()).unwrap();
            assert_eq!(data, *expected.fragment.facts());
            assert_eq!(metadata, *expected.fragment.metafacts());
        }
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn interrupted_prefix_resumes_to_the_same_complete_value() {
        let fixture = fixture();
        let plan = plan(&fixture.source).unwrap();

        publish_fragments(
            &fixture.pile,
            Some(&fixture.key),
            DEFAULT_SCOPE_ID,
            [plan.commits()[0].fragment.clone()],
        )
        .unwrap();
        publish(&fixture.source, &plan, &fixture.pile, Some(&fixture.key)).unwrap();

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection = faculties::collection_names::open(pile, DEFAULT_SCOPE_ID, signer);
        assert_eq!(collection.materialize().unwrap(), fixture.source_facts);
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn missing_signer_fails_before_target_growth() {
        let fixture = fixture();
        let plan = plan(&fixture.source).unwrap();
        fs::remove_file(&fixture.key).unwrap();
        let before = fs::metadata(&fixture.pile).unwrap().len();

        publish(&fixture.source, &plan, &fixture.pile, Some(&fixture.key)).unwrap_err();

        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), before);
    }
}
