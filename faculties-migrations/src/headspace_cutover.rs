//! Exact-additive stopped-world migration of the legacy Headspace branch.
//!
//! Migration changes storage authority, not history. Every verified authored
//! Repository commit becomes one independently signed native collection
//! commit with the same facts, entity ids, semantic metadata, and resident
//! blob closure. Authored empty commits remain commits; contentless merge
//! nodes remain verified source ancestry. Historical rows lack Headspace's
//! live marker and therefore remain inert evidence after publication.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::collection::{Collection, CollectionCommit};
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::BlobStore;
use triblespace::prelude::*;

use crate::collection_cutover::{project_legacy_authored_commits, FrozenSource, LegacyCommitCoordinate, LegacyPinCoordinate};
use faculties::storage::{load_signer, open_pile_strict};
use faculties::headspace as capability;
use faculties::schemas::headspace::{DEFAULT_SCOPE_ID, KIND_LIVE_RECORD, LEGACY_BRANCH_NAME};

/// One native commit projected from one verified legacy authored commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeadspaceMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
}

/// Conservation census for one complete Headspace migration plan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HeadspaceMigrationReport {
    pub authored_commits: usize,
    pub authored_empty_commits: usize,
    pub contentless_merges: usize,
    pub unique_facts: usize,
    pub fact_occurrences: usize,
    pub metafact_occurrences: usize,
    pub blob_occurrences: usize,
}

/// Pure stopped-world projection ready for native collection publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeadspaceMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<HeadspaceMigrationCommit>,
    original: TribleSet,
    report: HeadspaceMigrationReport,
}

impl HeadspaceMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[HeadspaceMigrationCommit] {
        &self.commits
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    pub const fn report(&self) -> &HeadspaceMigrationReport {
        &self.report
    }

    pub fn materialized_facts(&self) -> TribleSet {
        self.commits
            .iter()
            .flat_map(|commit| commit.fragment.facts().iter().copied())
            .collect()
    }

    /// Recheck exact preservation independently of publication.
    pub fn verify_conservation(&self) -> Result<()> {
        if self.materialized_facts() != self.original {
            bail!("planned Headspace collection does not exactly preserve legacy facts");
        }
        let fact_occurrences: usize = self
            .commits
            .iter()
            .map(|commit| commit.fragment.facts().len())
            .sum();
        let metafact_occurrences: usize = self
            .commits
            .iter()
            .map(|commit| commit.fragment.metafacts().len())
            .sum();
        let blob_occurrences: usize = self
            .commits
            .iter()
            .map(|commit| commit.fragment.blobs().len())
            .sum();
        if self.report.authored_commits != self.commits.len()
            || self.report.unique_facts != self.original.len()
            || self.report.fact_occurrences != fact_occurrences
            || self.report.metafact_occurrences != metafact_occurrences
            || self.report.blob_occurrences != blob_occurrences
        {
            bail!("Headspace migration report disagrees with its planned commits");
        }
        Ok(())
    }
}

fn has_live_marker(facts: &TribleSet) -> bool {
    exists!(pattern!(facts, [{ metadata::tag: KIND_LIVE_RECORD }]))
}

fn fragment_has_live_marker(fragment: &Fragment) -> bool {
    has_live_marker(fragment.facts()) || has_live_marker(fragment.metafacts())
}

/// Freeze and validate the complete named legacy Headspace branch.
pub fn plan(source: &FrozenSource) -> Result<HeadspaceMigrationPlan> {
    let branch = source
        .legacy_branch(LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Headspace branch"))?;
    let contentless_merges = branch
        .deltas
        .iter()
        .filter(|delta| !delta.is_authored())
        .count();
    // The projector returns deterministic parent-before-child order. Keeping
    // it makes every interrupted publication prefix a meaningful source
    // prefix instead of an arbitrary hash ordering.
    let projected =
        project_legacy_authored_commits(source, &branch, capability::validate_known_payloads)
            .context("project frozen Headspace authored commits")?;

    let source_pin = branch.pin_coordinate();
    let mut seen = BTreeSet::new();
    let mut original = TribleSet::new();
    let mut authored_empty_commits = 0;
    let mut fact_occurrences = 0;
    let mut metafact_occurrences = 0;
    let mut blob_occurrences = 0;
    let mut commits = Vec::with_capacity(projected.len());
    for projected in projected {
        if projected.source.branch != source_pin.id || projected.source.pin != source_pin.value {
            bail!("Headspace authored commits do not belong to one frozen branch pin");
        }
        if !seen.insert(projected.source) {
            bail!(
                "Headspace migration repeats legacy authored commit {}",
                hex::encode_upper(projected.source.commit.raw)
            );
        }
        if fragment_has_live_marker(&projected.content)
            || fragment_has_live_marker(&projected.metadata)
        {
            bail!(
                "legacy Headspace commit {} already carries the native live marker; refusing to activate source evidence",
                hex::encode_upper(projected.source.commit.raw)
            );
        }
        if projected.content.facts().is_empty() {
            authored_empty_commits += 1;
        }

        original += projected.content.facts().clone();
        let mut fragment = projected.content;
        fragment.describe_with(projected.metadata);
        fact_occurrences += fragment.facts().len();
        metafact_occurrences += fragment.metafacts().len();
        blob_occurrences += fragment.blobs().len();
        commits.push(HeadspaceMigrationCommit {
            source: projected.source,
            fragment,
        });
    }

    let plan = HeadspaceMigrationPlan {
        source_pin,
        report: HeadspaceMigrationReport {
            authored_commits: commits.len(),
            authored_empty_commits,
            contentless_merges,
            unique_facts: original.len(),
            fact_occurrences,
            metafact_occurrences,
            blob_occurrences,
        },
        commits,
        original,
    };
    plan.verify_conservation()?;
    Ok(plan)
}

/// Publish a complete plan through Headspace's fixed native collection.
///
/// Every legacy writer must remain stopped from source freeze through final
/// publication. The complete post-migration union is checked before the first
/// append. Exact replay, including any already-published prefix, is idempotent.
pub fn publish(
    source: &FrozenSource,
    plan: &HeadspaceMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Headspace migration plan does not belong to this frozen source");
    }
    plan.verify_conservation()?;

    // Authority must exist before the target pile is touched. The same open
    // pile owns preflight and every idempotent collection append.
    let signer = load_signer(target, key)?;
    let pile = open_pile_strict(target)?;
    let mut collection = Collection::new(pile, DEFAULT_SCOPE_ID, signer);
    let result = (|| {
        let existing = collection
            .materialize()
            .context("materialize existing native Headspace value")?;
        let reader = collection
            .storage_mut()
            .reader()
            .context("open Headspace publication attachment reader")?;

        let mut candidate = existing;
        for commit in &plan.commits {
            // This redundant publication-boundary check protects callers from
            // a forged in-memory plan assembled inside this crate.
            if fragment_has_live_marker(&commit.fragment) {
                bail!("Headspace migration candidate contains a live marker");
            }
            candidate += commit.fragment.facts().clone();
        }
        capability::validate_catalog(&reader, &candidate)
            .context("preflight complete post-migration Headspace union")?;

        let mut published = Vec::with_capacity(plan.commits.len());
        for commit in &plan.commits {
            published.push(
                collection
                    .commit(commit.fragment.clone())
                    .with_context(|| {
                        format!(
                            "publish Headspace commit projected from {}",
                            hex::encode_upper(commit.source.commit.raw)
                        )
                    })?,
            );
        }
        Ok(published)
    })();
    finish_pile(collection.into_storage(), result)
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    match (result, pile.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(anyhow!("close Headspace target pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Headspace target pile also failed: {close_error}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::sync::atomic::{AtomicU64, Ordering};

    use anybytes::View;
    use ed25519_dalek::SigningKey;
    use triblespace::core::attribute::Attribute;
    use triblespace::core::repo::{BlobStoreGet, BlobStoreList, PinStore, Repository};

    use super::*;
    use crate::collection_cutover::{freeze_source};
use faculties::storage::{initialize_signer};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-headspace-v4-cutover-{}-{serial}",
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
        profile: Id,
        content_payload: Inline<inlineencodings::Handle<blobencodings::RawBytes>>,
        metadata_payload: Inline<inlineencodings::Handle<blobencodings::RawBytes>>,
        source_facts: TribleSet,
    }

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn fixture() -> Fixture {
        fixture_with_live_marker(false)
    }

    fn fixture_with_live_marker(live: bool) -> Fixture {
        let directory = TestDirectory::new();
        let pile_path = directory.0.join("headspace.pile");
        let key = directory.0.join("headspace.key");
        File::create(&pile_path).unwrap();

        let pile = open_pile_strict(&pile_path).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0x61; 32]), Fragment::empty()).unwrap();
        let branch = *repository.create_branch(LEGACY_BRANCH_NAME, None).unwrap();
        let mut workspace = repository.pull(branch).unwrap();

        // Extrinsic ids and schema-unknown attachments are deliberate. The
        // migration must copy history, not rebuild it through today's entity
        // constructors or a whitelist of currently understood attributes.
        let profile = id(0x11);
        let opaque_content =
            Attribute::<inlineencodings::Handle<blobencodings::RawBytes>>::anchored(id(0x12));
        let opaque_metadata =
            Attribute::<inlineencodings::Handle<blobencodings::RawBytes>>::anchored(id(0x13));
        let mut profile_fragment = Fragment::empty();
        let name = profile_fragment
            .put::<blobencodings::LongString, _>("legacy headspace profile".to_owned());
        let content_payload =
            profile_fragment.put::<blobencodings::RawBytes, _>(b"future content payload".to_vec());
        profile_fragment += entity! { ExclusiveId::force_ref(&profile) @
            metadata::name: name,
            opaque_content: content_payload,
        };
        if live {
            profile_fragment += entity! { ExclusiveId::force_ref(&profile) @
                metadata::tag: &KIND_LIVE_RECORD,
            };
        }

        let mut semantic_metadata = Fragment::empty();
        let metadata_payload = semantic_metadata
            .put::<blobencodings::RawBytes, _>(b"future metadata payload".to_vec());
        semantic_metadata += entity! {
            opaque_metadata: metadata_payload,
        };
        workspace.commit_with_metadata(
            profile_fragment.clone(),
            semantic_metadata,
            "legacy profile provenance",
        );
        repository.push(&mut workspace).unwrap();

        // Two siblings force a verified contentless merge. One sibling is an
        // authored empty archive and must still become a native COMMIT.
        let mut authored = repository.pull(branch).unwrap();
        let mut authored_empty = repository.pull(branch).unwrap();
        let context = id(0x21);
        let mut context_fragment = Fragment::empty();
        let context_iri = context_fragment
            .put::<blobencodings::LongString, _>("urn:legacy:headspace:context".to_owned());
        context_fragment += entity! { ExclusiveId::force_ref(&context) @
            metadata::iri: context_iri,
        };
        authored.commit(context_fragment.clone(), "legacy context");
        authored_empty.commit(Fragment::empty(), "legacy authored empty");
        repository.push(&mut authored).unwrap();
        repository.push(&mut authored_empty).unwrap();
        repository.close().unwrap();

        let mut source_facts = profile_fragment.into_facts();
        source_facts += context_fragment.into_facts();
        initialize_signer(&pile_path, Some(&key)).unwrap();
        Fixture {
            _directory: directory,
            pile: pile_path,
            key,
            profile,
            content_payload,
            metadata_payload,
            source_facts,
        }
    }

    fn materialize(path: &Path, key: &Path) -> TribleSet {
        let signer = load_signer(path, Some(key)).unwrap();
        let pile = open_pile_strict(path).unwrap();
        let mut collection = Collection::new(pile, DEFAULT_SCOPE_ID, signer);
        let facts = collection.materialize().unwrap();
        collection.into_storage().close().unwrap();
        facts
    }

    fn plan_contains_blob(
        plan: &HeadspaceMigrationPlan,
        handle: Inline<inlineencodings::Handle<blobencodings::RawBytes>>,
    ) -> bool {
        plan.commits().iter().any(|commit| {
            let mut fragment = commit.fragment.clone();
            fragment
                .blobs_mut()
                .reader()
                .unwrap()
                .contains_blob(handle)
                .unwrap()
        })
    }

    #[test]
    fn plan_preserves_contentless_merge_authored_empty_and_resident_payloads() {
        let fixture = fixture();
        let frozen = freeze_source(&fixture.pile).unwrap();
        let plan = plan(&frozen).unwrap();

        plan.verify_conservation().unwrap();
        assert_eq!(plan.original_facts(), &fixture.source_facts);
        assert_eq!(plan.report().authored_commits, 3);
        assert_eq!(plan.report().authored_empty_commits, 1);
        assert_eq!(plan.report().contentless_merges, 1);
        assert!(plan.report().metafact_occurrences > 0);
        assert!(plan.report().blob_occurrences > 0);
        assert!(plan
            .materialized_facts()
            .iter()
            .any(|fact| fact.e() == &fixture.profile));
        assert!(plan.commits().iter().any(|commit| {
            commit.fragment.facts().is_empty() && !commit.fragment.metafacts().is_empty()
        }));
        assert!(plan_contains_blob(&plan, fixture.content_payload));
        assert!(plan_contains_blob(&plan, fixture.metadata_payload));

        let mut descriptions = Vec::new();
        for commit in plan.commits() {
            let mut fragment = commit.fragment.clone();
            let reader = fragment.blobs_mut().reader().unwrap();
            for fact in commit
                .fragment
                .metafacts()
                .iter()
                .filter(|fact| fact.a() == &metadata::description.id())
            {
                let handle = *fact.v::<inlineencodings::Handle<blobencodings::LongString>>();
                let value: View<str> = reader.get(handle).unwrap();
                descriptions.push(value.to_string());
            }
        }
        assert!(descriptions.contains(&"legacy profile provenance".to_owned()));
        assert!(descriptions.contains(&"legacy authored empty".to_owned()));
    }

    #[test]
    fn legacy_live_marker_is_rejected() {
        let fixture = fixture_with_live_marker(true);
        let frozen = freeze_source(&fixture.pile).unwrap();
        let error = plan(&frozen).unwrap_err();
        assert!(format!("{error:#}").contains("already carries the native live marker"));
    }

    #[test]
    fn publication_is_replay_safe_retains_pin_and_conserves_prior_native_union() {
        let fixture = fixture();
        let frozen = freeze_source(&fixture.pile).unwrap();
        let plan = plan(&frozen).unwrap();

        let prior_entity = id(0x31);
        let prior_attribute =
            Attribute::<inlineencodings::Handle<blobencodings::RawBytes>>::anchored(id(0x32));
        let mut prior = Fragment::empty();
        let prior_payload = prior.put::<blobencodings::RawBytes, _>(b"prior native".to_vec());
        prior += entity! { ExclusiveId::force_ref(&prior_entity) @
            prior_attribute: prior_payload,
        };
        let prior_facts = prior.facts().clone();
        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection = Collection::new(pile, DEFAULT_SCOPE_ID, signer);
        collection.commit(prior).unwrap();
        collection.into_storage().close().unwrap();

        let first = publish(&frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        let after_first = fs::metadata(&fixture.pile).unwrap().len();
        let replay = publish(&frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(replay, first);
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), after_first);

        let mut expected = fixture.source_facts.clone();
        expected += prior_facts;
        assert_eq!(materialize(&fixture.pile, &fixture.key), expected);

        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        assert_eq!(
            pile.head(plan.source_pin().id).unwrap(),
            Some(plan.source_pin().value)
        );
        pile.close().unwrap();
    }

    #[test]
    fn publication_resumes_from_an_interrupted_prefix() {
        let fixture = fixture();
        let frozen = freeze_source(&fixture.pile).unwrap();
        let plan = plan(&frozen).unwrap();

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection = Collection::new(pile, DEFAULT_SCOPE_ID, signer);
        let partial = collection
            .commit(plan.commits()[1].fragment.clone())
            .unwrap();
        collection.into_storage().close().unwrap();

        let resumed = publish(&frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(resumed[1], partial);
        assert_eq!(
            materialize(&fixture.pile, &fixture.key),
            fixture.source_facts
        );
    }

    #[test]
    fn invalid_prior_native_union_fails_before_any_migration_append() {
        let fixture = fixture();
        let frozen = freeze_source(&fixture.pile).unwrap();
        let plan = plan(&frozen).unwrap();

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection = Collection::new(pile, DEFAULT_SCOPE_ID, signer);
        collection
            .commit(entity! { metadata::tag: &KIND_LIVE_RECORD })
            .unwrap();
        collection.into_storage().close().unwrap();
        let before = fs::metadata(&fixture.pile).unwrap().len();

        let error = publish(&frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap_err();
        assert!(format!("{error:#}").contains("preflight complete"));
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), before);
    }

    #[test]
    fn missing_signer_fails_without_growing_target() {
        let fixture = fixture();
        let frozen = freeze_source(&fixture.pile).unwrap();
        let plan = plan(&frozen).unwrap();
        fs::remove_file(&fixture.key).unwrap();
        let before = fs::metadata(&fixture.pile).unwrap().len();

        let error = publish(&frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap_err();
        assert!(format!("{error:#}").contains("load durable signing key"));
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), before);
    }
}
