//! Stopped-world migration of the legacy Archive branch into its fixed V4
//! `SimpleArchive`-union collection.
//!
//! The transform is deliberately boring: every authored legacy commit becomes
//! one native collection commit with exactly the same facts, metafacts,
//! exports, entity ids, and resident blob closure. Contentless Repository
//! merges remain verified source ancestry and do not acquire collection
//! authority. No registry, ticket, mutable head, or legacy index manifest is
//! copied into the live collection calculus.

use std::collections::BTreeSet;
use std::path::Path;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::blobencodings::{LongString, RawBytes};
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;

use crate::blockdag::{self, CatalogValidation};
use crate::collection_cutover::{
    project_legacy_authored_commits, publish_fragments, FrozenSource, LegacyCommitCoordinate,
    LegacyPinCoordinate,
};
use crate::schemas::{blockdag as schema, files as files_schema};

/// Historical branch name used only as a read-only migration coordinate.
pub const LEGACY_BRANCH_NAME: &str = "archive";

/// One native commit projected from one authored legacy commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveMigrationCommit {
    pub source: LegacyCommitCoordinate,
    legacy_content: Fragment,
    legacy_metadata: Fragment,
    fragment: Fragment,
}

impl ArchiveMigrationCommit {
    pub fn legacy_content(&self) -> &Fragment {
        &self.legacy_content
    }

    pub fn legacy_metadata(&self) -> &Fragment {
        &self.legacy_metadata
    }

    pub fn fragment(&self) -> &Fragment {
        &self.fragment
    }
}

/// Conservation summary for one complete Archive branch migration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ArchiveMigrationReport {
    pub authored_commits: usize,
    pub facts: usize,
    pub metafacts: usize,
}

/// Pure stopped-world plan ready for descriptor-handle publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<ArchiveMigrationCommit>,
    original: TribleSet,
    report: ArchiveMigrationReport,
}

impl ArchiveMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[ArchiveMigrationCommit] {
        &self.commits
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    pub const fn report(&self) -> &ArchiveMigrationReport {
        &self.report
    }

    pub fn materialized_facts(&self) -> TribleSet {
        let mut facts = TribleSet::new();
        for commit in &self.commits {
            facts += commit.fragment.facts().clone();
        }
        facts
    }

    pub fn materialized_metafacts(&self) -> TribleSet {
        let mut facts = TribleSet::new();
        for commit in &self.commits {
            facts += commit.fragment.metafacts().clone();
        }
        facts
    }

    /// Recheck that the storage cutover changes no authored semantic value.
    pub fn verify_conservation(&self) -> Result<()> {
        for commit in &self.commits {
            verify_commit_preservation(commit)?;
        }
        if self.materialized_facts() != self.original {
            bail!("planned Archive collection does not exactly preserve legacy facts");
        }
        Ok(())
    }
}

/// Plan the complete legacy Archive branch without mutating its pile.
pub fn plan(source: &FrozenSource) -> Result<ArchiveMigrationPlan> {
    let branch = source
        .legacy_branch(LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Archive branch"))?;
    let mut projected = project_legacy_authored_commits(source, &branch, validate_known_payloads)
        .context("project frozen Archive authored commits")?;
    projected.sort_unstable_by_key(|commit| commit.source);

    for pair in projected.windows(2) {
        if pair[0].source == pair[1].source {
            bail!(
                "Archive migration input repeats legacy authored commit {}",
                hex::encode_upper(pair[0].source.commit.raw)
            );
        }
    }

    let source_pin = branch.pin_coordinate();
    let mut original = TribleSet::new();
    let mut commits = Vec::with_capacity(projected.len());
    for projected in projected {
        if projected.source.branch != source_pin.id || projected.source.pin != source_pin.value {
            bail!("Archive authored commits do not belong to one frozen branch pin");
        }
        original += projected.content.facts().clone();
        let legacy_content = projected.content;
        let legacy_metadata = projected.metadata;
        let mut fragment = legacy_content.clone();
        fragment.describe_with(legacy_metadata.clone());
        commits.push(ArchiveMigrationCommit {
            source: projected.source,
            legacy_content,
            legacy_metadata,
            fragment,
        });
    }

    require_accepted(
        blockdag::validate_catalog(source.reader(), &original)
            .context("validate complete frozen Archive block DAG")?,
        "frozen Archive block DAG",
    )?;

    let metafacts = commits
        .iter()
        .fold(TribleSet::new(), |mut all, commit| {
            all += commit.fragment.metafacts().clone();
            all
        })
        .len();
    let plan = ArchiveMigrationPlan {
        source_pin,
        report: ArchiveMigrationReport {
            authored_commits: commits.len(),
            facts: original.len(),
            metafacts,
        },
        commits,
        original,
    };
    plan.verify_conservation()?;
    Ok(plan)
}

/// Publish a verified plan through the fixed native Archive collection.
///
/// Every legacy writer must remain stopped from [`FrozenSource`] creation
/// through this call. Replaying any prefix or the complete plan is
/// content-addressed and idempotent.
pub fn publish(
    source: &FrozenSource,
    plan: &ArchiveMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Archive migration plan does not belong to this frozen source");
    }
    plan.verify_conservation()?;
    publish_fragments(
        target,
        key,
        schema::DEFAULT_SCOPE_ID,
        plan.commits.iter().map(|commit| commit.fragment.clone()),
    )
}

fn verify_commit_preservation(commit: &ArchiveMigrationCommit) -> Result<()> {
    if commit.fragment.facts() != commit.legacy_content.facts() {
        bail!(
            "Archive output commit {} changes authored content facts",
            hex::encode_upper(commit.source.commit.raw)
        );
    }

    let mut expected_metafacts = commit.legacy_content.metafacts().clone();
    expected_metafacts += commit.legacy_metadata.facts().clone();
    expected_metafacts += commit.legacy_metadata.metafacts().clone();
    if commit.fragment.metafacts() != &expected_metafacts {
        bail!(
            "Archive output commit {} changes authored or semantic metafacts",
            hex::encode_upper(commit.source.commit.raw)
        );
    }

    let expected_exports: BTreeSet<_> = commit.legacy_content.exports().collect();
    let actual_exports: BTreeSet<_> = commit.fragment.exports().collect();
    if actual_exports != expected_exports {
        bail!(
            "Archive output commit {} changes authored exports",
            hex::encode_upper(commit.source.commit.raw)
        );
    }

    let mut expected_blobs = commit.legacy_content.blobs().clone();
    expected_blobs.union(commit.legacy_metadata.blobs().clone());
    if commit.fragment.blobs() != &expected_blobs {
        bail!(
            "Archive output commit {} changes resident attachment closure",
            hex::encode_upper(commit.source.commit.raw)
        );
    }
    Ok(())
}

fn require_accepted(validation: CatalogValidation, label: &str) -> Result<()> {
    match validation {
        CatalogValidation::Accepted => Ok(()),
        CatalogValidation::Pending { missing } => bail!(
            "{label} is missing {} attachment blob(s): {}",
            missing.len(),
            missing
                .iter()
                .take(8)
                .map(hex::encode_upper)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        CatalogValidation::Rejected(reason) => bail!("{label} is invalid: {reason}"),
    }
}

/// Strictly load every direct blob handle known to the canonical Archive
/// vocabulary. Conservative closure hydration in `collection_cutover` then
/// preserves transitively resident blobs as well.
fn validate_known_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts {
        let text_field = if fact.a() == &schema::content_fact::payload.id() {
            Some("content_fact::payload")
        } else if fact.a() == &schema::content_fact::asset_pointer.id() {
            Some("content_fact::asset_pointer")
        } else if fact.a() == &schema::source_projection::source_locator.id() {
            Some("source_projection::source_locator")
        } else if fact.a() == &schema::source_projection::raw_author.id() {
            Some("source_projection::raw_author")
        } else if fact.a() == &schema::source_projection::raw_role.id() {
            Some("source_projection::raw_role")
        } else if fact.a() == &schema::source_projection::raw_model.id() {
            Some("source_projection::raw_model")
        } else if fact.a() == &files_schema::file::source_path.id() {
            Some("file::source_path")
        } else if fact.a() == &metadata::name.id() {
            Some("metadata::name")
        } else if fact.a() == &metadata::description.id() {
            Some("metadata::description")
        } else {
            None
        };
        if let Some(field) = text_field {
            let handle = *fact.v::<Handle<LongString>>();
            let _: View<str> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read legacy Archive {field} {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
            continue;
        }

        let raw_field = if fact.a() == &schema::content_fact::blob.id() {
            Some("content_fact::blob")
        } else if fact.a() == &schema::content_fact::resolved_to.id() {
            Some("content_fact::resolved_to")
        } else if fact.a() == &schema::source_projection::raw_record.id() {
            Some("source_projection::raw_record")
        } else {
            None
        };
        if let Some(field) = raw_field {
            let handle = *fact.v::<Handle<RawBytes>>();
            let _: anybytes::Bytes = reader.get(handle).with_context(|| {
                format!(
                    "strictly read legacy Archive {field} {}",
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

    use ed25519_dalek::SigningKey;
    use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace::core::collection::Collection;
    use triblespace::core::repo::{BlobStore, PinStore, Repository};
    use triblespace::macros::{find, pattern};

    use super::*;
    use crate::collection_cutover::{
        freeze_source, initialize_signer, load_signer, open_pile_strict,
    };

    struct Fixture {
        _directory: tempfile::TempDir,
        pile: std::path::PathBuf,
        key: std::path::PathBuf,
        projection: Id,
        facts: TribleSet,
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("archive.pile");
        let key = directory.path().join("archive.key");
        File::create(&pile).unwrap();

        let storage = open_pile_strict(&pile).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0xA4; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository.create_branch(LEGACY_BRANCH_NAME, None).unwrap();
        let mut workspace = repository.pull(branch).unwrap();

        let fact = blockdag::text_fact(
            schema::content_fact::modality::TEXT,
            schema::content_fact::direction::IN,
            "preserve this authored payload",
        )
        .unwrap();
        let part = blockdag::content_part(0, fact, None).unwrap();
        let block = blockdag::block([], None, part).unwrap();
        let content = blockdag::source_projection(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            "legacy-session:message",
            br#"{"uuid":"message"}"#.to_vec(),
            block,
        )
        .unwrap();
        let projection = content.root().unwrap();
        workspace.commit_with_metadata(
            content.clone(),
            entity! { metadata::description: "semantic Archive provenance" },
            "legacy Archive authored commit",
        );
        repository.push(&mut workspace).unwrap();

        // Authored empty commits are values, unlike contentless Repository
        // merges, and must retain their independent native metadata edge.
        workspace.commit_with_metadata(
            Fragment::empty(),
            entity! { metadata::description: "semantic empty provenance" },
            "legacy Archive authored empty commit",
        );
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();

        Fixture {
            _directory: directory,
            pile,
            key,
            projection,
            facts: content.into_facts(),
        }
    }

    #[test]
    fn stopped_world_plan_preserves_every_fragment_channel_and_public_id() {
        let fixture = fixture();
        let length = fs::metadata(&fixture.pile).unwrap().len();
        let frozen = freeze_source(&fixture.pile).unwrap();
        let plan = plan(&frozen).unwrap();

        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), length);
        plan.verify_conservation().unwrap();
        assert_eq!(plan.report().authored_commits, 2);
        assert_eq!(plan.original_facts(), &fixture.facts);
        assert_eq!(plan.materialized_facts(), fixture.facts);
        assert!(plan
            .materialized_facts()
            .iter()
            .any(|fact| fact.e() == &fixture.projection));
        for commit in plan.commits() {
            assert_eq!(commit.fragment().facts(), commit.legacy_content().facts());
        }
    }

    #[test]
    fn in_place_publication_is_idempotent_and_retains_legacy_evidence() {
        let fixture = fixture();
        let frozen = freeze_source(&fixture.pile).unwrap();
        let plan = plan(&frozen).unwrap();

        let first = publish(&frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(first.len(), 2);
        let after_first = fs::metadata(&fixture.pile).unwrap().len();
        let repeated = publish(&frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(repeated, first);
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), after_first);

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection = Collection::new(pile, schema::DEFAULT_SCOPE_ID, signer);
        let facts = collection.materialize().unwrap();
        assert_eq!(facts, fixture.facts);
        let reader = collection.storage_mut().reader().unwrap();
        let mut descriptions = BTreeSet::new();
        for commit in &first {
            let metadata: TribleSet = reader
                .get::<TribleSet, SimpleArchive>(commit.metadata())
                .unwrap();
            for handle in find!(
                value: Inline<Handle<LongString>>,
                pattern!(&metadata, [{ _?record @ metadata::description: ?value }])
            ) {
                let value: View<str> = reader.get(handle).unwrap();
                descriptions.insert(value.to_string());
            }
        }
        assert!(descriptions.contains("semantic Archive provenance"));
        assert!(descriptions.contains("semantic empty provenance"));
        assert!(descriptions.contains("legacy Archive authored commit"));
        assert!(descriptions.contains("legacy Archive authored empty commit"));
        let mut pile = collection.into_storage();
        assert!(pile.pins().unwrap().next().is_some());
        pile.close().unwrap();
    }

    #[test]
    fn exact_tf_bm25_attribute_rotation_remains_pinned() {
        assert_eq!(
            crate::schemas::archive::search_index::index.id(),
            Id::from_hex("BE3EF8A63DFD0C29993E93B8037BC2C7").unwrap()
        );
    }
}
