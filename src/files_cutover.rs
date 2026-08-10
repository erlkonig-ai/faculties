//! Pure, additive migration of the legacy Files branch into a native collection.
//!
//! The migration preserves every legacy fact and every existing entity id.
//! Its only semantic additions are canonical media-type entities and
//! `file::media_type` edges for historical files that only carried the inline
//! MIME attribute. Authored legacy commits remain independent collection
//! commits; contentless repository merges carry ancestry but create no new
//! authority.
//!
//! This module deliberately does **not** pretend that the live Files CLI has
//! already cut over. Live reads still need the next neutral seam: authorize
//! collection commits, resolve validated merge/derive equations, and
//! materialize the selected physical cover into a queryable snapshot. Until
//! that exists, retaining `Repository` behind a collection-shaped facade would
//! merely hide the old pin/CAS model.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::blob::encodings::longstring::LongString;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::genid::GenId;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::encodings::shortstring::ShortString;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::BlobStoreGet;
use triblespace::core::trible::{Fragment, Trible, TribleSet};
use triblespace::macros::{attributes, entity, find, pattern};
use triblespace::prelude::blobencodings::RawBytes;
use triblespace::prelude::ExclusiveId;
use triblespace_search::schemas::Embedding;

use crate::collection_cutover::{
    project_legacy_authored_commits, publish_fragments, FrozenSource, LegacyCommitCoordinate,
    LegacyPinCoordinate, ProjectedLegacyCommit,
};
use crate::files as file_capability;
use crate::schemas::embeddings;
use crate::schemas::files::{
    file, DEFAULT_SCOPE_ID, FILES_BRANCH_NAME, KIND_FILE, KIND_MEDIA_TYPE,
};

mod legacy {
    use super::*;

    attributes! {
        // Historical Files inline MIME field. The id is source vocabulary,
        // not a newly minted schema id.
        "BFE2C88ECD13D56F80967C343FC072EE" as mime: ShortString;
    }
}

/// Why one legacy inline MIME spelling produced the selected media type.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MediaTypeSource {
    LegacyValue,
    FilenameRecovery,
    GenericDefault,
}

/// Auditable additive decision for one preserved file entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MediaTypeDecision {
    pub file: Id,
    pub legacy_value: String,
    pub selected: String,
    pub source: MediaTypeSource,
    pub owner: LegacyCommitCoordinate,
}

/// One planned native commit corresponding to one legacy authored commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
}

/// Conservation summary for a complete Files branch migration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FilesMigrationReport {
    pub authored_commits: usize,
    pub original_facts: usize,
    pub added_facts: usize,
    pub files: usize,
    pub already_canonical: usize,
    pub migrated_media_types: usize,
    pub filename_recoveries: usize,
    pub generic_defaults: usize,
}

/// Pure stopped-world plan ready for native collection publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<FilesMigrationCommit>,
    original: TribleSet,
    extras: TribleSet,
    decisions: Vec<MediaTypeDecision>,
    report: FilesMigrationReport,
}

impl FilesMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[FilesMigrationCommit] {
        &self.commits
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    pub fn added_facts(&self) -> &TribleSet {
        &self.extras
    }

    pub fn decisions(&self) -> &[MediaTypeDecision] {
        &self.decisions
    }

    pub const fn report(&self) -> &FilesMigrationReport {
        &self.report
    }

    /// Union every planned authored leaf.
    pub fn materialized_facts(&self) -> TribleSet {
        let mut facts = TribleSet::new();
        for commit in &self.commits {
            facts += commit.fragment.facts().clone();
        }
        facts
    }

    /// Recheck the central migration law: output = old facts union extras.
    pub fn verify_conservation(&self) -> Result<()> {
        let mut expected = self.original.clone();
        expected += self.extras.clone();
        let actual = self.materialized_facts();
        if actual != expected {
            bail!("planned Files collection is not exactly old facts union additive extras");
        }
        if self.extras.iter().any(|fact| self.original.contains(fact)) {
            bail!("Files migration classifies an existing fact as an additive extra");
        }
        for extra in &self.extras {
            let occurrences = self
                .commits
                .iter()
                .filter(|commit| commit.fragment.facts().contains(extra))
                .count();
            if occurrences != 1 {
                bail!(
                    "additive Files fact is assigned to {occurrences} authored commits; expected exactly one"
                );
            }
        }
        Ok(())
    }
}

/// Plan the complete legacy Files branch without mutating either pile.
pub fn plan(source: &FrozenSource) -> Result<FilesMigrationPlan> {
    let branch = source
        .legacy_branch(FILES_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Files branch"))?;
    let projected = project_legacy_authored_commits(source, &branch, validate_known_payloads)
        .context("project frozen Files authored commits")?;
    plan_projected(branch.pin_coordinate(), projected, source.reader())
}

/// Publish a previously computed plan through the native collection facade.
///
/// The source was verified once when [`FrozenSource`] captured its immutable
/// reader. Migration is a stopped-world operation: callers must keep legacy
/// writers stopped through publication. This function deliberately does not
/// reopen and revalidate the entire source pile around target writes.
pub fn publish(
    source: &FrozenSource,
    plan: &FilesMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Files migration plan does not belong to this frozen source");
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
    reader: &PileReader,
) -> Result<FilesMigrationPlan> {
    projected.sort_unstable_by_key(|commit| commit.source);
    for pair in projected.windows(2) {
        if pair[0].source == pair[1].source {
            bail!(
                "Files input repeats legacy authored commit {}",
                hex::encode_upper(pair[0].source.commit.raw)
            );
        }
    }
    for commit in &projected {
        if commit.source.branch != source_pin.id || commit.source.pin != source_pin.value {
            bail!("Files authored commits do not belong to one frozen branch pin");
        }
    }

    let mut original = TribleSet::new();
    let mut witnesses: BTreeMap<Trible, BTreeSet<LegacyCommitCoordinate>> = BTreeMap::new();
    for commit in &projected {
        original += commit.content.facts().clone();
        for fact in commit.content.facts() {
            witnesses.entry(*fact).or_default().insert(commit.source);
        }
    }

    let file_ids: BTreeSet<Id> = find!(
        id: Id,
        pattern!(&original, [{ ?id @ metadata::tag: &KIND_FILE }])
    )
    .collect();
    let mut additions: BTreeMap<LegacyCommitCoordinate, Fragment> = BTreeMap::new();
    let mut media_types: BTreeMap<String, (Id, LegacyCommitCoordinate)> = BTreeMap::new();
    let mut file_edges = Vec::new();
    let mut extras = TribleSet::new();
    let mut decisions = Vec::new();
    let mut already_canonical = 0;

    for file_id in &file_ids {
        let name_fact = exactly_one_fact(&original, *file_id, file::name.id(), "file name")?;
        let name_handle = *name_fact.v::<Handle<LongString>>();
        let name: View<str> = reader
            .get(name_handle)
            .with_context(|| format!("read filename attachment for {file_id:x}"))?;

        let current_media = facts_for(&original, *file_id, file::media_type.id());
        if current_media.len() > 1 {
            bail!("file {file_id:x} has multiple canonical media-type relations");
        }
        if let Some(current) = current_media.first() {
            let media_type: Id = current
                .v::<GenId>()
                .try_from_inline()
                .map_err(|_| anyhow!("file {file_id:x} has an invalid media-type id"))?;
            validate_existing_media_type(&original, reader, media_type)?;
            already_canonical += 1;
            continue;
        }

        let mime_fact = exactly_one_fact(&original, *file_id, legacy::mime.id(), "legacy MIME")?;
        let legacy_value: String = mime_fact
            .v::<ShortString>()
            .try_from_inline()
            .map_err(|error| anyhow!("decode legacy MIME for {file_id:x}: {error:?}"))?;
        let (selected, source_kind) = choose_media_type(name.as_ref(), &legacy_value);

        let media_type = media_type_fragment(&selected)?
            .root()
            .expect("media type fragment has one root");

        // The global derivation depends on all three exact source facts. Those
        // facts may have been repeated or introduced by different authored
        // commits, so its support is the union of their immutable coordinates.
        // Attribution chooses the least coordinate from that complete support
        // set; it does not claim that one commit introduced every input.
        let kind_fact = original
            .iter()
            .find(|fact| {
                fact.e() == file_id
                    && fact.a() == &metadata::tag.id()
                    && fact
                        .v::<GenId>()
                        .try_from_inline::<Id>()
                        .is_ok_and(|kind| kind == KIND_FILE)
            })
            .copied()
            .expect("file query supplied its kind fact");
        let owner = [kind_fact, name_fact, mime_fact]
            .into_iter()
            .flat_map(|fact| witnesses.get(&fact).into_iter().flatten().copied())
            .min()
            .ok_or_else(|| anyhow!("file {file_id:x} additions have no authored witness"))?;
        match media_types.entry(selected.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((media_type, owner));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let (existing, media_owner) = entry.get_mut();
                if *existing != media_type {
                    bail!("canonical media type {selected:?} derived inconsistent ids");
                }
                *media_owner = (*media_owner).min(owner);
            }
        }
        file_edges.push((owner, *file_id, media_type));
        decisions.push(MediaTypeDecision {
            file: *file_id,
            legacy_value,
            selected,
            source: source_kind,
            owner,
        });
    }

    // Shared media-type entity facts are emitted once even when many files
    // select the same type. File-specific edges remain independently owned.
    for (name, (expected_id, owner)) in media_types {
        let addition = media_type_fragment(&name)?;
        if addition.root() != Some(expected_id) {
            bail!("canonical media type {name:?} changed identity while planning");
        }
        assign_addition(&original, &mut extras, &mut additions, owner, addition);
    }
    for (owner, file_id, media_type) in file_edges {
        assign_addition(
            &original,
            &mut extras,
            &mut additions,
            owner,
            entity! { ExclusiveId::force_ref(&file_id) @
                file::media_type: &media_type,
            },
        );
    }

    decisions.sort();
    let mut commits = Vec::with_capacity(projected.len());
    for mut legacy in projected {
        if let Some(addition) = additions.remove(&legacy.source) {
            legacy.content += addition;
        }
        legacy.content.describe_with(legacy.metadata);
        commits.push(FilesMigrationCommit {
            source: legacy.source,
            fragment: legacy.content,
        });
    }
    if !additions.is_empty() {
        bail!("Files planner produced additions for an absent authored commit");
    }

    let report = FilesMigrationReport {
        authored_commits: commits.len(),
        original_facts: original.len(),
        added_facts: extras.len(),
        files: file_ids.len(),
        already_canonical,
        migrated_media_types: decisions.len(),
        filename_recoveries: decisions
            .iter()
            .filter(|decision| decision.source == MediaTypeSource::FilenameRecovery)
            .count(),
        generic_defaults: decisions
            .iter()
            .filter(|decision| decision.source == MediaTypeSource::GenericDefault)
            .count(),
    };
    let plan = FilesMigrationPlan {
        source_pin,
        commits,
        original,
        extras,
        decisions,
        report,
    };
    plan.verify_conservation()?;
    Ok(plan)
}

fn assign_addition(
    original: &TribleSet,
    extras: &mut TribleSet,
    additions: &mut BTreeMap<LegacyCommitCoordinate, Fragment>,
    owner: LegacyCommitCoordinate,
    addition: Fragment,
) {
    let (_, facts, metafacts, blobs) = addition.into_parts();
    let unique = facts.difference(original);
    if unique.is_empty() {
        return;
    }
    *extras += unique.clone();
    *additions.entry(owner).or_default() += Fragment::from_parts(unique, metafacts, blobs);
}

fn facts_for(facts: &TribleSet, entity: Id, attribute: Id) -> Vec<Trible> {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity && fact.a() == &attribute)
        .copied()
        .collect()
}

fn exactly_one_fact(facts: &TribleSet, entity: Id, attribute: Id, field: &str) -> Result<Trible> {
    let values = facts_for(facts, entity, attribute);
    if values.len() != 1 {
        bail!(
            "file {entity:x} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(values[0])
}

fn validate_existing_media_type(
    facts: &TribleSet,
    reader: &PileReader,
    media_type: Id,
) -> Result<()> {
    let tagged = find!(
        id: Id,
        pattern!(facts, [{ media_type @ metadata::tag: ?id }])
    )
    .any(|id| id == KIND_MEDIA_TYPE);
    if !tagged {
        bail!("file points at non-media-type entity {media_type:x}");
    }
    let name_fact = exactly_one_fact(facts, media_type, metadata::name.id(), "media-type name")?;
    let handle = *name_fact.v::<Handle<LongString>>();
    let name: View<str> = reader
        .get(handle)
        .with_context(|| format!("read media-type name for {media_type:x}"))?;
    let normalized = file_capability::normalize_media_type(name.as_ref())?;
    if normalized != name.as_ref() {
        bail!("media-type entity {media_type:x} stores a non-normalized name");
    }
    let canonical = media_type_fragment(name.as_ref())?;
    if canonical.root() != Some(media_type) {
        bail!("file points at non-intrinsic media-type entity {media_type:x}");
    }
    Ok(())
}

fn media_type_fragment(media_type: &str) -> Result<Fragment> {
    let media_type = file_capability::normalize_media_type(media_type)?;
    let mut fragment = Fragment::empty();
    let name = fragment.put::<LongString, _>(media_type);
    fragment += entity! {
        metadata::tag: &KIND_MEDIA_TYPE,
        metadata::name: name,
    };
    Ok(fragment)
}

fn choose_media_type(name: &str, legacy_value: &str) -> (String, MediaTypeSource) {
    let inferred = file_capability::infer_media_type(Path::new(name));
    match file_capability::normalize_media_type(legacy_value) {
        Ok(normalized)
            if legacy_value.len() == 32
                && inferred != file_capability::DEFAULT_MEDIA_TYPE
                && normalized != inferred =>
        {
            (inferred.to_owned(), MediaTypeSource::FilenameRecovery)
        }
        Ok(normalized) => (normalized, MediaTypeSource::LegacyValue),
        Err(_) if inferred != file_capability::DEFAULT_MEDIA_TYPE => {
            (inferred.to_owned(), MediaTypeSource::FilenameRecovery)
        }
        Err(_) => (
            file_capability::DEFAULT_MEDIA_TYPE.to_owned(),
            MediaTypeSource::GenericDefault,
        ),
    }
}

/// Strictly read every Files payload whose encoding is known to this domain.
fn validate_known_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts {
        if fact.a() == &file::content.id() {
            let handle = *fact.v::<Handle<RawBytes>>();
            let _: anybytes::Bytes = reader.get(handle).with_context(|| {
                format!("strictly read file content {}", hex::encode(handle.raw))
            })?;
        } else if fact.a() == &file::name.id()
            || fact.a() == &file::source_path.id()
            || fact.a() == &metadata::name.id()
            || fact.a() == &metadata::description.id()
        {
            let handle = *fact.v::<Handle<LongString>>();
            let _: View<str> = reader
                .get(handle)
                .with_context(|| format!("strictly read Files text {}", hex::encode(handle.raw)))?;
        } else if fact.a() == &file::embedding.id() {
            let handle = *fact.v::<Handle<Embedding>>();
            let _: View<[f32]> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read Files CLIP embedding {}",
                    hex::encode(handle.raw)
                )
            })?;
        } else if fact.a() == &embeddings::attr::embedding.id() {
            let handle = *fact.v::<Handle<embeddings::Embedding768>>();
            let _: View<[f32]> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read Files 768-d embedding {}",
                    hex::encode(handle.raw)
                )
            })?;
        } else if fact.a() == &embeddings::attr_mm7b::embedding.id() {
            let handle = *fact.v::<Handle<embeddings::Embedding3584>>();
            let _: View<[f32]> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read Files 3584-d embedding {}",
                    hex::encode(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::{self, File};
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace::core::inline::Inline;
    use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStorePut, PinStore, Repository};
    use triblespace::macros::exists;

    use crate::collection_cutover::{discover_target, freeze_source, initialize_signer};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-files-cutover-{}-{serial}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Fixture {
        _directory: TestDirectory,
        source: std::path::PathBuf,
        target: std::path::PathBuf,
        key: std::path::PathBuf,
        old_file: Id,
        old_second_file: Id,
        old_directory: Id,
        source_facts: TribleSet,
    }

    fn fixture() -> Fixture {
        let directory = TestDirectory::new();
        let source = directory.path().join("legacy.pile");
        let target = directory.path().join("native.pile");
        let key = directory.path().join("native.key");
        File::create(&source).unwrap();
        File::create(&target).unwrap();

        let pile = crate::collection_cutover::open_pile_strict(&source).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0x51; 32]), Fragment::empty()).unwrap();
        let branch = *repository.create_branch(FILES_BRANCH_NAME, None).unwrap();
        let mut workspace = repository.pull(branch).unwrap();

        let mut file_fragment = Fragment::empty();
        let content = file_fragment.put::<RawBytes, _>(b"legacy PDF".to_vec());
        let name = file_fragment.put::<LongString, _>("report.pdf".to_owned());
        let file_record = entity! {
            metadata::tag: &KIND_FILE,
            file::content: content,
            file::name: name,
            legacy::mime: "application/pdf",
        };
        let old_file = file_record.root().unwrap();
        file_fragment += file_record;
        let semantic = entity! { metadata::description: "semantic metadata" };
        workspace.commit_with_metadata(file_fragment.clone(), semantic, "legacy file");
        repository.push(&mut workspace).unwrap();

        let mut directory_fragment = Fragment::empty();
        let second_content = directory_fragment.put::<RawBytes, _>(b"second PDF".to_vec());
        let second_name = directory_fragment.put::<LongString, _>("appendix.pdf".to_owned());
        let second_file = entity! {
            metadata::tag: &KIND_FILE,
            file::content: second_content,
            file::name: second_name,
            legacy::mime: "application/pdf",
        };
        let old_second_file = second_file.root().unwrap();
        directory_fragment += second_file;
        let directory_record = entity! {
            metadata::tag: &crate::schemas::files::KIND_DIRECTORY,
            file::name: "docs",
            file::children*: [old_file, old_second_file],
        };
        let old_directory = directory_record.root().unwrap();
        directory_fragment += directory_record;
        let mut authored_empty = repository.pull(branch).unwrap();
        authored_empty.commit(Fragment::empty(), "authored empty");
        workspace.commit(directory_fragment.clone(), "legacy directory");
        repository.push(&mut workspace).unwrap();
        repository.push(&mut authored_empty).unwrap();
        repository.close().unwrap();

        let mut source_facts = file_fragment.into_facts();
        source_facts += directory_fragment.into_facts();
        initialize_signer(&target, Some(&key)).unwrap();
        Fixture {
            _directory: directory,
            source,
            target,
            key,
            old_file,
            old_second_file,
            old_directory,
            source_facts,
        }
    }

    #[test]
    fn plan_is_strictly_additive_and_preserves_every_existing_identity() {
        let fixture = fixture();
        let before = fs::read(&fixture.source).unwrap();
        let frozen = freeze_source(&fixture.source).unwrap();
        let plan = plan(&frozen).unwrap();

        assert_eq!(fs::read(&fixture.source).unwrap(), before);
        assert_eq!(plan.original_facts(), &fixture.source_facts);
        plan.verify_conservation().unwrap();
        let materialized = plan.materialized_facts();
        for fact in &fixture.source_facts {
            assert!(materialized.contains(fact));
        }
        assert!(exists!(pattern!(&materialized, [{
            fixture.old_directory @ file::children: fixture.old_file
        }])));
        assert!(exists!(pattern!(&materialized, [{
            fixture.old_directory @ file::children: fixture.old_second_file
        }])));
        let media_type = find!(
            media_type: Id,
            pattern!(&materialized, [{ fixture.old_file @ file::media_type: ?media_type }])
        )
        .next()
        .expect("additive media type relation");
        assert!(exists!(pattern!(&materialized, [{
            media_type @ metadata::tag: &KIND_MEDIA_TYPE
        }])));
        assert_eq!(plan.decisions().len(), 2);
        assert!(plan.decisions().iter().all(|decision| {
            decision.selected == "application/pdf"
                && [fixture.old_file, fixture.old_second_file].contains(&decision.file)
        }));
        assert_eq!(plan.report().original_facts, fixture.source_facts.len());
        assert_eq!(plan.report().migrated_media_types, 2);
        assert_eq!(plan.report().authored_commits, 3);
    }

    #[test]
    fn native_publication_replays_without_growth_or_legacy_target_pins() {
        let fixture = fixture();
        let frozen = freeze_source(&fixture.source).unwrap();
        let plan = plan(&frozen).unwrap();

        let first = publish(&frozen, &plan, &fixture.target, Some(&fixture.key)).unwrap();
        let after_first = fs::metadata(&fixture.target).unwrap().len();
        let second = publish(&frozen, &plan, &fixture.target, Some(&fixture.key)).unwrap();
        let after_second = fs::metadata(&fixture.target).unwrap().len();
        assert_eq!(first, second);
        assert_eq!(after_first, after_second);

        let mut pile = crate::collection_cutover::open_pile_strict(&fixture.target).unwrap();
        assert!(pile
            .pins()
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
            .is_empty());
        let target = discover_target(&mut pile, DEFAULT_SCOPE_ID).unwrap();
        assert!(target.definition_present());
        let mut expected_commits = first.clone();
        expected_commits.sort_unstable_by_key(CollectionCommit::id);
        assert_eq!(target.commits(), expected_commits.as_slice());
        assert!(target.merges().is_empty());
        assert!(target.derives().is_empty());
        assert!(target.diagnostics().is_empty());

        let reader = pile.reader().unwrap();
        let mut materialized = TribleSet::new();
        let mut materialized_metadata = TribleSet::new();
        for commit in target.commits() {
            materialized += reader
                .get::<TribleSet, SimpleArchive>(Handle::from_hash(commit.data()))
                .unwrap();
            materialized_metadata += reader
                .get::<TribleSet, SimpleArchive>(commit.metadata())
                .unwrap();
        }
        assert_eq!(materialized, plan.materialized_facts());
        validate_known_payloads(&reader, &materialized).unwrap();
        validate_known_payloads(&reader, &materialized_metadata).unwrap();
        let descriptions: BTreeSet<String> = find!(
            description: Inline<Handle<LongString>>,
            pattern!(&materialized_metadata, [{
                _?metadata @ metadata::description: ?description
            }])
        )
        .map(|handle| reader.get::<View<str>, _>(handle).unwrap().to_string())
        .collect();
        assert!(descriptions.contains("semantic metadata"));
        assert!(descriptions.contains("legacy file"));
        assert!(descriptions.contains("legacy directory"));
        pile.close().unwrap();
    }

    #[test]
    fn native_publication_can_append_to_the_frozen_legacy_pile() {
        let fixture = fixture();
        initialize_signer(&fixture.source, Some(&fixture.key)).unwrap();
        let frozen = freeze_source(&fixture.source).unwrap();
        let plan = plan(&frozen).unwrap();

        let first = publish(&frozen, &plan, &fixture.source, Some(&fixture.key)).unwrap();
        let after_first = fs::metadata(&fixture.source).unwrap().len();
        let second = publish(&frozen, &plan, &fixture.source, Some(&fixture.key)).unwrap();
        assert_eq!(first, second);
        assert_eq!(fs::metadata(&fixture.source).unwrap().len(), after_first);

        let mut pile = crate::collection_cutover::open_pile_strict(&fixture.source).unwrap();
        assert!(!pile
            .pins()
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
            .is_empty());
        let target = discover_target(&mut pile, DEFAULT_SCOPE_ID).unwrap();
        assert_eq!(target.commits().len(), plan.commits().len());
        pile.close().unwrap();
    }

    #[test]
    fn malformed_file_without_any_media_evidence_is_rejected() {
        let directory = TestDirectory::new();
        let source = directory.path().join("malformed.pile");
        File::create(&source).unwrap();
        let pile = crate::collection_cutover::open_pile_strict(&source).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0x61; 32]), Fragment::empty()).unwrap();
        let branch = *repository.create_branch(FILES_BRANCH_NAME, None).unwrap();
        let mut workspace = repository.pull(branch).unwrap();
        let mut malformed = Fragment::empty();
        let content = malformed.put::<RawBytes, _>(b"missing MIME".to_vec());
        let name = malformed.put::<LongString, _>("missing.bin".to_owned());
        malformed += entity! {
            metadata::tag: &KIND_FILE,
            file::content: content,
            file::name: name,
        };
        workspace.commit(malformed, "malformed");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();

        let frozen = freeze_source(&source).unwrap();
        let error = plan(&frozen).unwrap_err();
        assert!(format!("{error:#}").contains("legacy MIME"));
    }

    #[test]
    fn existing_media_type_must_have_its_intrinsic_identity() {
        let directory = TestDirectory::new();
        let path = directory.path().join("media-type.pile");
        File::create(&path).unwrap();
        let mut pile = crate::collection_cutover::open_pile_strict(&path).unwrap();
        let name = pile
            .put::<LongString, _>("application/pdf".to_owned())
            .unwrap();
        let extrinsic = Id::new([0x71; 16]).unwrap();
        let facts = entity! { ExclusiveId::force_ref(&extrinsic) @
            metadata::tag: &KIND_MEDIA_TYPE,
            metadata::name: name,
        }
        .into_facts();
        let reader = pile.reader().unwrap();
        pile.close().unwrap();

        let error = validate_existing_media_type(&facts, &reader, extrinsic).unwrap_err();
        assert!(format!("{error:#}").contains("non-intrinsic media-type"));
    }
}
