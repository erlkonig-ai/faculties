//! Exact stopped-world migration of the legacy Web Repository branch.
//!
//! Search and fetch observations are already monotone evidence. Every authored
//! Repository commit therefore becomes one independently signed native COMMIT
//! without rewriting an entity, fact, public id, semantic metadata fact, or
//! resident attachment. Authored empty commits remain authored members;
//! contentless Repository merge nodes are verified ancestry only.

use std::collections::HashSet;
use std::path::Path;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::*;

use crate::collection_cutover::{
    project_legacy_authored_commits, FrozenSource, LegacyCommitCoordinate, LegacyPinCoordinate,
};
use crate::write_authority::publish_fragments;
use faculties::schemas::web::{web_schema, DEFAULT_SCOPE_ID, LEGACY_BRANCH_NAME};

/// One native COMMIT projected from one verified legacy authored commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
}

/// Conservation summary for one complete Web migration plan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WebMigrationReport {
    pub authored_commits: usize,
    pub authored_empty_commits: usize,
    pub contentless_merges: usize,
    pub facts: usize,
}

/// Pure stopped-world plan ready for native collection publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<WebMigrationCommit>,
    original: TribleSet,
    report: WebMigrationReport,
}

impl WebMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[WebMigrationCommit] {
        &self.commits
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    pub const fn report(&self) -> &WebMigrationReport {
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
            bail!("planned Web collection does not exactly preserve legacy facts");
        }
        if self.report.authored_commits != self.commits.len()
            || self.report.facts != self.original.len()
        {
            bail!("Web migration report disagrees with its planned commits");
        }
        Ok(())
    }
}

/// Plan the complete named legacy Web branch without mutating its pile.
pub fn plan(source: &FrozenSource) -> Result<WebMigrationPlan> {
    let branch = source
        .legacy_branch(LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Web branch"))?;
    let contentless_merges = branch
        .deltas
        .iter()
        .filter(|delta| !delta.is_authored())
        .count();
    let projected = project_legacy_authored_commits(source, &branch, validate_known_payloads)
        .context("project frozen Web authored commits")?;

    let source_pin = branch.pin_coordinate();
    let mut seen = std::collections::BTreeSet::new();
    let mut original = TribleSet::new();
    let mut authored_empty_commits = 0;
    let mut commits = Vec::with_capacity(projected.len());
    for projected in projected {
        if projected.source.branch != source_pin.id || projected.source.pin != source_pin.value {
            bail!("Web authored commits do not belong to one frozen branch pin");
        }
        if !seen.insert(projected.source) {
            bail!(
                "Web migration repeats legacy authored commit {}",
                hex::encode_upper(projected.source.commit.raw)
            );
        }
        if projected.content.facts().is_empty() {
            authored_empty_commits += 1;
        }
        original += projected.content.facts().clone();
        let mut fragment = projected.content;
        fragment.describe_with(projected.metadata);
        commits.push(WebMigrationCommit {
            source: projected.source,
            fragment,
        });
    }

    let plan = WebMigrationPlan {
        source_pin,
        report: WebMigrationReport {
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

/// Publish the verified plan into the one fixed native Web collection.
///
/// Exact replay and interrupted-prefix recovery are content addressed and
/// idempotent. The legacy pin is never modified or removed.
pub fn publish(
    source: &FrozenSource,
    plan: &WebMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Web migration plan does not belong to this frozen source");
    }
    plan.verify_conservation()?;
    publish_fragments(
        target,
        key,
        DEFAULT_SCOPE_ID,
        plan.commits.iter().map(|commit| commit.fragment.clone()),
    )
}

/// Strictly load every direct attachment named by the published Web schema.
///
/// The generic projector separately preserves the complete resident closure,
/// so unknown future attributes survive without this validator interpreting
/// or filtering them.
pub fn validate_known_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    let text_attributes = [
        web_schema::query.id(),
        web_schema::url.id(),
        web_schema::title.id(),
        web_schema::snippet.id(),
        web_schema::content.id(),
        metadata::name.id(),
        metadata::description.id(),
        metadata::source.id(),
        metadata::iri.id(),
    ]
    .into_iter()
    .collect::<HashSet<_>>();

    for fact in facts {
        if text_attributes.contains(fact.a()) {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::UTF8String>>();
            let _: View<str> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read frozen Web text payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::collection_cutover::test_support::{TestBranchSpec, TestDeltaSpec, TestSourceSpec};
    use faculties::storage::{initialize_signer, load_signer, open_pile_strict};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-web-cutover-{}-{serial}",
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
        facts: TribleSet,
        source: FrozenSource,
    }

    fn observation(label: &str) -> Fragment {
        let mut fragment = Fragment::empty();
        let query = fragment.put::<blobencodings::UTF8String, _>(label.to_owned());
        let url = fragment.put::<blobencodings::UTF8String, _>(format!("https://{label}.test"));
        fragment += entity! { _ @
            metadata::tag: &web_schema::kind_search,
            web_schema::query: query,
            web_schema::provider: "test",
            web_schema::url: url,
        };
        fragment
    }

    fn fixture() -> Fixture {
        let directory = TestDirectory::new();
        let pile = directory.0.join("web.pile");
        let key = directory.0.join("web.key");
        File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        let first = observation("first");
        let second = observation("second");
        let mut facts = first.facts().clone();
        facts += second.facts().clone();
        let source = TestSourceSpec::new(vec![TestBranchSpec::new(
            LEGACY_BRANCH_NAME,
            Id::new([0x77; 16]).unwrap(),
            SigningKey::from_bytes(&[0x77; 32]),
            vec![
                TestDeltaSpec::authored(first, "first")
                    .with_metadata(entity! { metadata::description: "legacy Web provenance" }),
                TestDeltaSpec::authored(second, "second"),
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
            facts,
            source,
        }
    }

    #[test]
    fn exact_plan_preserves_authorship_and_merge_ancestry() {
        let fixture = fixture();
        let plan = plan(&fixture.source).unwrap();

        assert_eq!(plan.original_facts(), &fixture.facts);
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
        let length = fs::metadata(&fixture.pile).unwrap().len();
        let second = publish(&fixture.source, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(first, second);
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), length);

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection = faculties::collection_names::open(pile, DEFAULT_SCOPE_ID, signer);
        assert_eq!(collection.materialize().unwrap(), fixture.facts);
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn interrupted_prefix_resumes_and_missing_signer_cannot_grow_target() {
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

        fs::remove_file(&fixture.key).unwrap();
        let before = fs::metadata(&fixture.pile).unwrap().len();
        publish(&fixture.source, &plan, &fixture.pile, Some(&fixture.key)).unwrap_err();
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), before);
    }
}
