//! Additive, authored-leaf migration of the legacy Wiki branch.
//!
//! Every verified authored repository commit becomes one independent native
//! collection commit. Contentless merges remain source ancestry and acquire no
//! collection authority. Legacy facts, ids, attachments, and commit metadata
//! are retained; the only new semantic facts are supersedes edges that make
//! the already-displayed timestamp lineage explicit.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::prelude::*;

use crate::collection_cutover::{project_legacy_authored_commits, FrozenSource, LegacyCommitCoordinate, LegacyPinCoordinate, ProjectedLegacyCommit};
use faculties::storage::{publish_fragments};
use faculties::schemas::wiki::{DEFAULT_SCOPE_ID, LEGACY_BRANCH_NAME};
use faculties::wiki_additive::{plan_additive, LegacyDelta};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WikiMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WikiMigrationReport {
    pub authored_commits: usize,
    pub original_facts: usize,
    pub added_facts: usize,
    pub versions: usize,
    pub fragments: usize,
    pub ties: usize,
    pub ties_at: Vec<(Id, Id, Id)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WikiMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<WikiMigrationCommit>,
    original: TribleSet,
    extras: TribleSet,
    report: WikiMigrationReport,
}

impl WikiMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[WikiMigrationCommit] {
        &self.commits
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    pub fn added_facts(&self) -> &TribleSet {
        &self.extras
    }

    pub const fn report(&self) -> &WikiMigrationReport {
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
        expected += self.extras.clone();
        if self.materialized_facts() != expected {
            bail!("planned Wiki collection is not exactly old facts union additive lineage");
        }
        if self.extras.iter().any(|fact| self.original.contains(fact)) {
            bail!("Wiki migration classifies an existing fact as an additive extra");
        }
        for extra in &self.extras {
            let owners = self
                .commits
                .iter()
                .filter(|commit| commit.fragment.facts().contains(extra))
                .count();
            if owners != 1 {
                bail!(
                    "additive Wiki fact is assigned to {owners} authored commits; expected exactly one"
                );
            }
        }
        Ok(())
    }
}

pub fn plan(source: &FrozenSource) -> Result<WikiMigrationPlan> {
    let branch = source
        .legacy_branch(LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Wiki branch"))?;
    let projected =
        project_legacy_authored_commits(source, &branch, faculties::wiki::validate_known_payloads)
            .context("project frozen Wiki authored commits")?;
    let plan = plan_projected(branch.pin_coordinate(), projected)?;
    faculties::wiki::validate_catalog(source.reader(), &plan.materialized_facts())
        .context("validate complete planned Wiki catalog and payloads")?;
    Ok(plan)
}

pub fn publish(
    source: &FrozenSource,
    plan: &WikiMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Wiki migration plan does not belong to this frozen source");
    }
    plan.verify_conservation()?;
    publish_fragments(
        target,
        key,
        DEFAULT_SCOPE_ID,
        plan.commits.iter().map(|commit| commit.fragment.clone()),
    )
}

fn plan_projected(
    source_pin: LegacyPinCoordinate,
    mut projected: Vec<ProjectedLegacyCommit>,
) -> Result<WikiMigrationPlan> {
    projected.sort_unstable_by_key(|commit| commit.source);
    for pair in projected.windows(2) {
        if pair[0].source == pair[1].source {
            bail!(
                "Wiki input repeats legacy authored commit {}",
                hex::encode_upper(pair[0].source.commit.raw)
            );
        }
    }
    for commit in &projected {
        if commit.source.branch != source_pin.id || commit.source.pin != source_pin.value {
            bail!("Wiki authored commits do not belong to one frozen branch pin");
        }
    }

    let mut original = TribleSet::new();
    let mut observation_witnesses: BTreeMap<(Id, [u8; 32]), BTreeSet<LegacyCommitCoordinate>> =
        BTreeMap::new();
    let deltas: Vec<LegacyDelta> = projected
        .iter()
        .map(|commit| {
            original += commit.content.facts().clone();
            for fact in commit.content.facts() {
                if fact.a() == &metadata::created_at.id() {
                    let observed = *fact.v::<inlineencodings::NsTAIInterval>();
                    observation_witnesses
                        .entry((*fact.e(), observed.raw))
                        .or_default()
                        .insert(commit.source);
                }
            }
            LegacyDelta {
                commit: commit.content.root().unwrap_or(commit.source.branch),
                facts: commit.content.facts().clone(),
            }
        })
        .collect();
    let additive = plan_additive(&deltas).map_err(|malformed| {
        anyhow!(
            "legacy Wiki lineage is malformed: {} undated, {} unfragmented, {} with several fragments (expected exactly one each)",
            malformed.undated.len(),
            malformed.unfragmented.len(),
            malformed.ambiguous.len()
        )
    })?;
    if additive.versions != additive.tagged {
        bail!(
            "legacy Wiki inventory differs: {} fragment-bearing versions, {} tagged versions",
            additive.versions,
            additive.tagged
        );
    }

    let extras = additive.facts.difference(&original);
    let mut additions: BTreeMap<LegacyCommitCoordinate, Fragment> = BTreeMap::new();
    for (later, earlier) in find!(
        (later: Id, earlier: Id),
        pattern!(&extras, [{ ?later @ metadata::supersedes: ?earlier }])
    ) {
        let selected = additive
            .selected_created_at(later)
            .ok_or_else(|| anyhow!("lineage addition for {later:x} has no ordering observation"))?;
        let owner = observation_witnesses
            .get(&(later, selected.raw))
            .and_then(|owners| owners.first())
            .copied()
            .ok_or_else(|| {
                anyhow!(
                    "lineage addition for {later:x} has no authored witness carrying its selected created-at"
                )
            })?;
        let addition = additions.entry(owner).or_insert_with(Fragment::empty);
        *addition += entity! { ExclusiveId::force_ref(&later) @
            metadata::supersedes: &earlier,
        };
    }

    let mut commits = Vec::with_capacity(projected.len());
    for projected in projected {
        let mut fragment = projected.content;
        if let Some(addition) = additions.remove(&projected.source) {
            fragment += addition;
        }
        fragment.describe_with(projected.metadata);
        commits.push(WikiMigrationCommit {
            source: projected.source,
            fragment,
        });
    }
    if !additions.is_empty() {
        bail!("Wiki lineage additions remain without an authored leaf");
    }

    let plan = WikiMigrationPlan {
        source_pin,
        report: WikiMigrationReport {
            authored_commits: commits.len(),
            original_facts: original.len(),
            added_facts: extras.len(),
            versions: additive.versions,
            fragments: additive.fragments,
            ties: additive.ties,
            ties_at: additive.ties_at,
        },
        commits,
        original,
        extras,
    };
    plan.verify_conservation()?;
    faculties::wiki::load_catalog(&plan.materialized_facts())
        .context("validate complete planned Wiki structure before publication")?;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};

    use anybytes::View;
    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace::core::inline::encodings::hash::Handle;
    use triblespace::core::repo::{BlobStoreGet, CommitHandle, PinStore, Repository};
    use triblespace::macros::exists;

    use crate::collection_cutover::{freeze_source};
use faculties::storage::{discover_target, initialize_signer, load_signer, open_pile_strict};
    use faculties::schemas::wiki::{attrs, KIND_VERSION_ID};

    fn at(seconds: f64) -> Inline<inlineencodings::NsTAIInterval> {
        let epoch = Epoch::from_tai_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn handle(byte: u8) -> Inline<Handle<SimpleArchive>> {
        Inline::new([byte; 32])
    }

    fn coordinate(
        branch: Id,
        pin: Inline<Handle<SimpleArchive>>,
        byte: u8,
    ) -> LegacyCommitCoordinate {
        LegacyCommitCoordinate {
            branch,
            pin,
            commit: CommitHandle::new([byte; 32]),
        }
    }

    fn version(id: Id, fragment: Id, body: &str, seconds: f64) -> Fragment {
        let mut output = Fragment::empty();
        let title = output.put::<blobencodings::LongString, _>("Title".to_owned());
        let content = output.put::<blobencodings::LongString, _>(body.to_owned());
        output += entity! { ExclusiveId::force_ref(&id) @
            metadata::tag: &KIND_VERSION_ID,
            attrs::fragment: fragment,
            attrs::title: title,
            attrs::content: content,
            metadata::created_at: at(seconds),
        };
        output
    }

    #[test]
    fn authored_leaves_preserve_every_fact_and_own_each_new_edge_once() {
        let branch = genid().id;
        let pin = handle(3);
        let page = genid().id;
        let first = genid().id;
        let second = genid().id;
        let first_coordinate = coordinate(branch, pin, 4);
        let second_coordinate = coordinate(branch, pin, 5);
        let mut first_fragment = version(first, page, "one", 1.0);
        first_fragment += entity! { ExclusiveId::force_ref(&first) @ attrs::links_to: &second };
        let projected = vec![
            ProjectedLegacyCommit {
                source: first_coordinate,
                content: first_fragment.clone(),
                metadata: entity! { metadata::description: "first legacy commit" },
            },
            ProjectedLegacyCommit {
                source: second_coordinate,
                content: version(second, page, "two", 2.0),
                metadata: entity! { metadata::description: "second legacy commit" },
            },
            ProjectedLegacyCommit {
                source: coordinate(branch, pin, 6),
                content: Fragment::empty(),
                metadata: entity! { metadata::description: "authored empty commit" },
            },
        ];
        let plan = plan_projected(
            LegacyPinCoordinate {
                id: branch,
                value: pin,
            },
            projected,
        )
        .unwrap();

        assert_eq!(plan.commits().len(), 3, "one leaf per authored commit");
        for fact in first_fragment.facts() {
            assert!(plan.original_facts().contains(fact));
            assert!(plan.materialized_facts().contains(fact));
        }
        assert_eq!(plan.added_facts().len(), 1);
        let later = plan
            .commits()
            .iter()
            .find(|commit| commit.source == second_coordinate)
            .unwrap();
        assert!(find!(
            (earlier: Id),
            pattern!(&later.fragment, [{
                second @ metadata::supersedes: ?earlier
            }])
        )
        .any(|(earlier,)| earlier == first));
        plan.verify_conservation().unwrap();
    }

    #[test]
    fn reasserted_state_keeps_all_times_and_remains_the_migrated_frontier() {
        let branch = genid().id;
        let pin = handle(20);
        let page = genid().id;
        let state_a = genid().id;
        let state_b = genid().id;
        let first_a = at(1.0);
        let reverted_a = at(3.0);
        let first_a_source = coordinate(branch, pin, 21);
        let state_b_source = coordinate(branch, pin, 22);
        let reverted_a_source = coordinate(branch, pin, 23);
        let projected = vec![
            ProjectedLegacyCommit {
                source: first_a_source,
                content: version(state_a, page, "A", 1.0),
                metadata: Fragment::empty(),
            },
            ProjectedLegacyCommit {
                source: state_b_source,
                content: version(state_b, page, "B", 2.0),
                metadata: Fragment::empty(),
            },
            ProjectedLegacyCommit {
                source: reverted_a_source,
                content: version(state_a, page, "A", 3.0),
                metadata: Fragment::empty(),
            },
        ];

        let plan = plan_projected(
            LegacyPinCoordinate {
                id: branch,
                value: pin,
            },
            projected,
        )
        .unwrap();
        let materialized = plan.materialized_facts();

        assert!(exists!(pattern!(&plan.original, [{
            state_a @ metadata::created_at: first_a
        }])));
        assert!(exists!(pattern!(&plan.original, [{
            state_a @ metadata::created_at: reverted_a
        }])));
        assert!(exists!(pattern!(&materialized, [{
            state_a @ metadata::supersedes: &state_b
        }])));
        let first_assertion = plan
            .commits()
            .iter()
            .find(|commit| commit.source == first_a_source)
            .unwrap();
        let revert_assertion = plan
            .commits()
            .iter()
            .find(|commit| commit.source == reverted_a_source)
            .unwrap();
        assert!(!exists!(pattern!(&first_assertion.fragment, [{
            state_a @ metadata::supersedes: &state_b
        }])));
        assert!(exists!(pattern!(&revert_assertion.fragment, [{
            state_a @ metadata::supersedes: &state_b
        }])));
        assert_eq!(plan.report().versions, 2);
        assert_eq!(plan.report().added_facts, 1);

        let model = faculties::wiki::load_catalog(&materialized).unwrap().revisions;
        let entry = model.entry_containing(state_a).unwrap();
        assert_eq!(
            entry
                .frontier
                .iter()
                .map(|head| head.id)
                .collect::<Vec<_>>(),
            vec![state_a],
            "A(1), B(2), A(3) must migrate with reasserted A current"
        );
        assert_eq!(
            model.revision(state_a).unwrap().legacy_created_at,
            BTreeSet::from([first_a, reverted_a])
        );
        plan.verify_conservation().unwrap();
    }

    #[test]
    fn exact_replanning_is_idempotent_and_does_not_duplicate_existing_edges() {
        let branch = genid().id;
        let pin = handle(9);
        let page = genid().id;
        let first = genid().id;
        let second = genid().id;
        let mut later = version(second, page, "two", 2.0);
        later += entity! { ExclusiveId::force_ref(&second) @
            metadata::supersedes: &first,
        };
        let input = vec![
            ProjectedLegacyCommit {
                source: coordinate(branch, pin, 10),
                content: version(first, page, "one", 1.0),
                metadata: Fragment::empty(),
            },
            ProjectedLegacyCommit {
                source: coordinate(branch, pin, 11),
                content: later,
                metadata: Fragment::empty(),
            },
        ];
        let pin_coordinate = LegacyPinCoordinate {
            id: branch,
            value: pin,
        };
        let first_plan = plan_projected(pin_coordinate, input.clone()).unwrap();
        let second_plan = plan_projected(pin_coordinate, input).unwrap();
        assert_eq!(first_plan.added_facts().len(), 0);
        assert_eq!(first_plan, second_plan);
    }

    #[test]
    fn malformed_legacy_value_is_refused_before_publication() {
        let branch = genid().id;
        let pin = handle(12);
        let page = genid().id;
        let conflicting_page = genid().id;
        let revision = genid().id;
        let mut malformed = version(revision, page, "body", 1.0);
        malformed += entity! { ExclusiveId::force_ref(&revision) @
            attrs::fragment: conflicting_page,
        };
        let projected = vec![ProjectedLegacyCommit {
            source: coordinate(branch, pin, 13),
            content: malformed,
            metadata: Fragment::empty(),
        }];

        let error = plan_projected(
            LegacyPinCoordinate {
                id: branch,
                value: pin,
            },
            projected,
        )
        .unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("expected exactly one"));
    }

    #[test]
    fn native_publication_is_idempotent_and_targets_the_descriptor_handle() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("legacy.pile");
        let target_path = directory.path().join("native.pile");
        let key_path = directory.path().join("native.key");
        File::create(&source_path).unwrap();
        File::create(&target_path).unwrap();

        let storage = open_pile_strict(&source_path).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0x41; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository.create_branch(LEGACY_BRANCH_NAME, None).unwrap();
        let mut main = repository.pull(branch).unwrap();
        let page = genid().id;
        let first = genid().id;
        let second = genid().id;
        let first_fragment = version(first, page, "one", 1.0);
        main.commit(first_fragment.clone(), "first Wiki version");
        repository.push(&mut main).unwrap();

        let mut authored_empty = repository.pull(branch).unwrap();
        authored_empty.commit(Fragment::empty(), "authored empty");
        let second_fragment = version(second, page, "two", 2.0);
        main.commit(second_fragment.clone(), "second Wiki version");
        repository.push(&mut main).unwrap();
        repository.push(&mut authored_empty).unwrap();
        repository.close().unwrap();
        initialize_signer(&target_path, Some(&key_path)).unwrap();

        let source_bytes = fs::read(&source_path).unwrap();
        let frozen = freeze_source(&source_path).unwrap();
        let plan = plan(&frozen).unwrap();
        assert_eq!(fs::read(&source_path).unwrap(), source_bytes);
        assert_eq!(plan.report().authored_commits, 3);
        assert_eq!(plan.report().added_facts, 1);

        let first_publish = publish(&frozen, &plan, &target_path, Some(&key_path)).unwrap();
        let length = fs::metadata(&target_path).unwrap().len();
        let second_publish = publish(&frozen, &plan, &target_path, Some(&key_path)).unwrap();
        assert_eq!(first_publish, second_publish);
        assert_eq!(fs::metadata(&target_path).unwrap().len(), length);

        let mut target = open_pile_strict(&target_path).unwrap();
        assert!(target
            .pins()
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
            .is_empty());
        let discovered = discover_target(&mut target, DEFAULT_SCOPE_ID).unwrap();
        assert_eq!(
            discovered.descriptor(),
            triblespace::core::collection::simplearchive_union::descriptor(DEFAULT_SCOPE_ID)
        );
        assert_eq!(discovered.commits().len(), 3);
        assert!(discovered.merges().is_empty());
        assert!(discovered.derives().is_empty());
        assert!(discovered.diagnostics().is_empty());

        let signer = load_signer(&target_path, Some(&key_path)).unwrap();
        let materialized = Collection::new(&mut target, DEFAULT_SCOPE_ID, signer)
            .materialize()
            .unwrap();
        assert_eq!(materialized, plan.materialized_facts());
        assert!(exists!(pattern!(&materialized, [{
            second @ metadata::supersedes: &first
        }])));

        let reader = target.reader().unwrap();
        let content = find!(
            handle: faculties::schemas::wiki::TextHandle,
            pattern!(&materialized, [{ second @ attrs::content: ?handle }])
        )
        .next()
        .unwrap();
        let content: View<str> = reader.get(content).unwrap();
        assert_eq!(&*content, "two");
        let descriptions: BTreeSet<String> = discovered
            .commits()
            .iter()
            .flat_map(|commit| {
                let facts: TribleSet = reader.get(commit.metadata()).unwrap();
                find!(
                    description: Inline<inlineencodings::Handle<blobencodings::LongString>>,
                    pattern!(&facts, [{
                        _?metadata @ metadata::description: ?description
                    }])
                )
                .map(|handle| reader.get::<View<str>, _>(handle).unwrap().to_string())
                .collect::<Vec<_>>()
            })
            .collect();
        assert!(descriptions.contains("first Wiki version"));
        assert!(descriptions.contains("second Wiki version"));
        assert!(descriptions.contains("authored empty"));
        target.close().unwrap();
    }
}
