//! Stopped-world migration of the legacy Compass branch into its native
//! collection.
//!
//! The transform is strictly additive: every authored legacy commit becomes
//! one independent collection commit with exactly the same facts and entity
//! ids. Contentless repository merges remain verified source ancestry but do
//! not acquire collection authority. Existing notes and supersession links
//! therefore retain their public identities; no ontology rewrite is hidden in
//! the storage cutover.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::collection::CollectionCommit;
use triblespace::prelude::*;

use crate::collection_cutover::{
    project_legacy_authored_commits, publish_fragments, FrozenSource, LegacyCommitCoordinate,
    LegacyPinCoordinate,
};
use crate::schemas::compass::DEFAULT_SCOPE_ID;

pub use crate::schemas::compass::LEGACY_BRANCH_NAME;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompassMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompassMigrationReport {
    pub authored_commits: usize,
    pub facts: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompassMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<CompassMigrationCommit>,
    original: TribleSet,
    report: CompassMigrationReport,
}

impl CompassMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[CompassMigrationCommit] {
        &self.commits
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    pub const fn report(&self) -> &CompassMigrationReport {
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
        if self.materialized_facts() != self.original {
            bail!("planned Compass collection does not exactly preserve legacy facts");
        }
        Ok(())
    }
}

pub fn plan(source: &FrozenSource) -> Result<CompassMigrationPlan> {
    let branch = source
        .legacy_branch(LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Compass branch"))?;
    let mut projected =
        project_legacy_authored_commits(source, &branch, crate::compass::validate_known_payloads)
            .context("project frozen Compass authored commits")?;
    projected.sort_unstable_by_key(|commit| commit.source);

    for pair in projected.windows(2) {
        if pair[0].source == pair[1].source {
            bail!(
                "Compass migration input repeats legacy authored commit {}",
                hex::encode_upper(pair[0].source.commit.raw)
            );
        }
    }

    let source_pin = branch.pin_coordinate();
    let mut original = TribleSet::new();
    let mut commits = Vec::with_capacity(projected.len());
    for projected in projected {
        if projected.source.branch != source_pin.id || projected.source.pin != source_pin.value {
            bail!("Compass authored commits do not belong to one frozen branch pin");
        }
        original += projected.content.facts().clone();
        let mut fragment = projected.content;
        fragment.describe_with(projected.metadata);
        commits.push(CompassMigrationCommit {
            source: projected.source,
            fragment,
        });
    }

    let plan = CompassMigrationPlan {
        source_pin,
        report: CompassMigrationReport {
            authored_commits: commits.len(),
            facts: original.len(),
        },
        commits,
        original,
    };
    plan.verify_conservation()?;
    Ok(plan)
}

pub fn publish(
    source: &FrozenSource,
    plan: &CompassMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Compass migration plan does not belong to this frozen source");
    }
    plan.verify_conservation()?;
    publish_fragments(
        target,
        key,
        DEFAULT_SCOPE_ID,
        plan.commits.iter().map(|commit| commit.fragment.clone()),
    )
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use triblespace::core::collection::Collection;
    use triblespace::core::metadata;
    use triblespace::core::repo::Repository;
    use triblespace::macros::entity;

    use super::*;
    use crate::collection_cutover::{
        freeze_source, initialize_signer, load_signer, open_pile_strict,
    };
    use crate::schemas::compass::{board, KIND_GOAL_ID, KIND_NOTE_ID, KIND_STATUS_ID};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-compass-cutover-{}-{serial}",
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
        goal: Id,
        note: Id,
        source_facts: TribleSet,
    }

    fn fixture() -> Fixture {
        let directory = TestDirectory::new();
        let pile = directory.0.join("compass.pile");
        let key = directory.0.join("compass.key");
        File::create(&pile).unwrap();

        let storage = open_pile_strict(&pile).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0x61; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository.create_branch(LEGACY_BRANCH_NAME, None).unwrap();
        let mut workspace = repository.pull(branch).unwrap();
        let goal = genid().id;
        let note = genid().id;
        let status = genid().id;
        let first_time = Epoch::from_unix_seconds(10.0);
        let first_time: Inline<inlineencodings::NsTAIInterval> =
            (first_time, first_time).try_to_inline().unwrap();

        let mut first = Fragment::empty();
        let title = first.put::<blobencodings::LongString, _>("Preserve me".to_owned());
        first += entity! { ExclusiveId::force_ref(&goal) @
            metadata::tag: &KIND_GOAL_ID,
            board::title: title,
            metadata::created_at: first_time,
            board::tag: "native",
        };
        first += entity! { ExclusiveId::force_ref(&status) @
            metadata::tag: &KIND_STATUS_ID,
            board::task: &goal,
            board::status: "doing",
            metadata::created_at: first_time,
        };
        workspace.commit_with_metadata(
            first.clone(),
            entity! { metadata::description: "legacy Compass provenance" },
            "legacy goal",
        );
        repository.push(&mut workspace).unwrap();

        let second_time = Epoch::from_unix_seconds(20.0);
        let second_time: Inline<inlineencodings::NsTAIInterval> =
            (second_time, second_time).try_to_inline().unwrap();
        let mut second = Fragment::empty();
        let body = second.put::<blobencodings::LongString, _>("exact old note".to_owned());
        second += entity! { ExclusiveId::force_ref(&note) @
            metadata::tag: &KIND_NOTE_ID,
            board::task: &goal,
            board::note: body,
            metadata::created_at: second_time,
        };
        workspace.commit(second.clone(), "legacy note");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();

        let mut source_facts = first.into_facts();
        source_facts += second.into_facts();
        initialize_signer(&pile, Some(&key)).unwrap();
        Fixture {
            _directory: directory,
            pile,
            key,
            goal,
            note,
            source_facts,
        }
    }

    #[test]
    fn plan_is_strictly_additive_and_preserves_public_ids() {
        let fixture = fixture();
        let frozen = freeze_source(&fixture.pile).unwrap();
        let plan = plan(&frozen).unwrap();

        plan.verify_conservation().unwrap();
        assert_eq!(plan.original_facts(), &fixture.source_facts);
        assert_eq!(plan.report().authored_commits, 2);
        assert!(crate::compass::goal_ids(&plan.materialized_facts()).contains(&fixture.goal));
        assert!(crate::compass::note_ids(&plan.materialized_facts()).contains(&fixture.note));
    }

    #[test]
    fn publication_is_idempotent_and_retains_legacy_coordinates() {
        let fixture = fixture();
        let frozen = freeze_source(&fixture.pile).unwrap();
        let plan = plan(&frozen).unwrap();

        let first = publish(&frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        let length = fs::metadata(&fixture.pile).unwrap().len();
        let second = publish(&frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(first, second);
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), length);

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let storage = open_pile_strict(&fixture.pile).unwrap();
        let mut collection = Collection::new(storage, DEFAULT_SCOPE_ID, signer);
        let facts = collection.materialize().unwrap();
        assert_eq!(facts, fixture.source_facts);
        collection.into_storage().close().unwrap();
    }
}
