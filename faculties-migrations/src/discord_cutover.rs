//! Exact stopped-world migration of the legacy Discord Repository branch.
//!
//! Every authored legacy commit becomes one independently signed native
//! collection COMMIT with facts, public entity ids, semantic metadata, and
//! resident blob closure preserved byte-for-byte. Contentless Repository
//! merges are verified ancestry only; authored empty commits remain authored
//! collection members. No legacy row is retyped into the native observation
//! model: old tokens, scalar cursors, mutable message rows, and log-shaped
//! evidence survive additively but remain inert.

use std::path::Path;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::*;

use crate::collection_cutover::{
    project_legacy_authored_commits, FrozenSource, LegacyCommitCoordinate, LegacyPinCoordinate,
};
use faculties::discord;
use faculties::schemas::archive::archive;
use faculties::schemas::discord::{discord as schema, DEFAULT_SCOPE_ID, LEGACY_BRANCH_NAME};
use faculties::storage::{load_signer, open_pile_strict};

/// One exact native COMMIT projected from one authored legacy commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiscordMigrationReport {
    pub authored_commits: usize,
    pub authored_empty_commits: usize,
    pub contentless_merges: usize,
    pub facts: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<DiscordMigrationCommit>,
    original: TribleSet,
    report: DiscordMigrationReport,
}

impl DiscordMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[DiscordMigrationCommit] {
        &self.commits
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    pub const fn report(&self) -> &DiscordMigrationReport {
        &self.report
    }

    pub fn materialized_facts(&self) -> TribleSet {
        self.commits
            .iter()
            .fold(TribleSet::new(), |mut facts, commit| {
                facts += commit.fragment.facts().clone();
                facts
            })
    }

    pub fn verify_conservation(&self) -> Result<()> {
        if self.materialized_facts() != self.original {
            bail!("planned Discord collection does not exactly preserve legacy facts");
        }
        if self.report.authored_commits != self.commits.len()
            || self.report.facts != self.original.len()
        {
            bail!("Discord migration report does not describe its plan");
        }
        Ok(())
    }
}

/// Plan the complete legacy branch from one immutable stopped-world snapshot.
pub fn plan(source: &FrozenSource) -> Result<DiscordMigrationPlan> {
    let branch = source
        .legacy_branch(LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Discord branch"))?;
    let contentless_merges = branch
        .deltas
        .iter()
        .filter(|delta| !delta.is_authored())
        .count();
    let mut projected = project_legacy_authored_commits(source, &branch, validate_known_payloads)
        .context("project frozen Discord authored commits")?;
    projected.sort_unstable_by_key(|commit| commit.source);
    for pair in projected.windows(2) {
        if pair[0].source == pair[1].source {
            bail!(
                "Discord migration repeats legacy authored commit {}",
                hex::encode_upper(pair[0].source.commit.raw)
            );
        }
    }

    let source_pin = branch.pin_coordinate();
    let mut original = TribleSet::new();
    let mut authored_empty_commits = 0;
    let mut commits = Vec::with_capacity(projected.len());
    for projected in projected {
        if projected.source.branch != source_pin.id || projected.source.pin != source_pin.value {
            bail!("Discord authored commits do not belong to one frozen branch pin");
        }
        if projected.content.facts().is_empty() {
            authored_empty_commits += 1;
        }
        original += projected.content.facts().clone();
        let mut fragment = projected.content;
        fragment.describe_with(projected.metadata);
        commits.push(DiscordMigrationCommit {
            source: projected.source,
            fragment,
        });
    }

    let plan = DiscordMigrationPlan {
        source_pin,
        report: DiscordMigrationReport {
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

/// Publish a complete verified plan through the fixed Discord collection.
///
/// Every legacy writer must remain stopped from source freeze through this
/// call. The complete post-migration union is validated before the first
/// append; exact replay and arbitrary interrupted-prefix recovery are content
/// addressed and idempotent.
pub fn publish(
    source: &FrozenSource,
    plan: &DiscordMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Discord migration plan does not belong to this frozen source");
    }
    plan.verify_conservation()?;

    let signer = load_signer(target, key)?;
    let pile = open_pile_strict(target)?;
    let mut collection = faculties::collection_names::open(pile, DEFAULT_SCOPE_ID, signer);
    let result = (|| {
        let existing = collection
            .materialize()
            .context("materialize existing native Discord value")?;
        let reader = collection
            .storage_mut()
            .reader()
            .context("open Discord publication attachment reader")?;
        let staged = plan
            .commits
            .iter()
            .fold(Fragment::empty(), |mut all, commit| {
                all += commit.fragment.clone();
                all
            });
        discord::validate_candidate(&reader, &existing, &staged)
            .context("preflight existing native value union legacy Discord plan")?;

        let mut published = Vec::with_capacity(plan.commits.len());
        for commit in &plan.commits {
            published.push(
                collection
                    .commit(commit.fragment.clone())
                    .with_context(|| {
                        format!(
                            "publish Discord commit projected from {}",
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
    let close = pile.close();
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(anyhow!("close Discord target pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Discord target pile also failed: {close_error}"
        ))),
    }
}

/// Strictly load every direct handle whose historical schema is known. The
/// shared projector separately carries the conservative reachable closure, so
/// unknown future attributes are retained rather than interpreted or dropped.
fn validate_known_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    let text_attributes = [
        schema::guild_id.id(),
        schema::channel_id.id(),
        schema::message_id.id(),
        schema::user_id.id(),
        schema::message_raw.id(),
        schema::bot_token.id(),
        schema::cursor_last_message_id.id(),
        archive::content.id(),
        archive::author_name.id(),
        archive::attachment_source_id.id(),
        archive::attachment_source_pointer.id(),
        archive::attachment_name.id(),
        metadata::name.id(),
        metadata::description.id(),
    ];
    for fact in facts {
        if text_attributes.contains(fact.a()) {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::UTF8String>>();
            let _: View<str> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read legacy Discord text payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        } else if fact.a() == &archive::attachment_data.id() {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::RawBytes>>();
            let _: anybytes::Bytes = reader.get(handle).with_context(|| {
                format!(
                    "strictly read legacy Discord attachment payload {}",
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
    use hifitime::Epoch;
    use triblespace::core::metadata;

    use super::*;
    use crate::collection_cutover::test_support::{TestBranchSpec, TestDeltaSpec, TestSourceSpec};
    use faculties::storage::{discover_target, initialize_signer, load_signer, open_pile_strict};

    struct Fixture {
        _directory: tempfile::TempDir,
        pile: std::path::PathBuf,
        key: std::path::PathBuf,
        source_facts: TribleSet,
        message: Id,
        source: FrozenSource,
    }

    fn at(seconds: f64) -> Inline<inlineencodings::NsTAIInterval> {
        let epoch = Epoch::from_tai_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("discord.pile");
        let key = directory.path().join("discord.key");
        File::create(&pile_path).unwrap();
        initialize_signer(&pile_path, Some(&key)).unwrap();
        let message = Id::new([0x31; 16]).unwrap();
        let mut message_fragment = Fragment::empty();
        let external =
            message_fragment.put::<blobencodings::UTF8String, _>("100000000000000001".to_owned());
        let content = message_fragment
            .put::<blobencodings::UTF8String, _>("legacy Discord content".to_owned());
        let raw =
            message_fragment.put::<blobencodings::UTF8String, _>("{\"legacy\":true}".to_owned());
        message_fragment += entity! { ExclusiveId::force_ref(&message) @
            metadata::tag: archive::kind_message,
            schema::message_id: external,
            schema::message_raw: raw,
            archive::content: content,
        };
        let token_left = Id::new([0x32; 16]).unwrap();
        let token_right = Id::new([0x33; 16]).unwrap();
        let left_fragment =
            entity! { ExclusiveId::force_ref(&token_left) @ schema::bot_token: "left-secret" };
        let right_fragment =
            entity! { ExclusiveId::force_ref(&token_right) @ schema::bot_token: "right-secret" };
        let mut source_facts = message_fragment.facts().clone();
        source_facts += left_fragment.facts().clone();
        source_facts += right_fragment.facts().clone();
        // Two children from the same base feed one canonical contentless merge.
        let source = TestSourceSpec::new(vec![TestBranchSpec::new(
            LEGACY_BRANCH_NAME,
            Id::new([0x6D; 16]).unwrap(),
            SigningKey::from_bytes(&[0x6D; 32]),
            vec![
                TestDeltaSpec::authored(message_fragment, "legacy Discord message")
                    .with_metadata(entity! { metadata::description: "legacy Discord provenance" }),
                TestDeltaSpec::authored(Fragment::empty(), "legacy authored empty"),
                TestDeltaSpec::authored(left_fragment, "legacy left token"),
                TestDeltaSpec::authored(right_fragment, "legacy right token").with_parents([1]),
                TestDeltaSpec::merge([2, 3]),
            ],
        )])
        .freeze(&pile_path)
        .unwrap()
        .source;
        Fixture {
            _directory: directory,
            pile: pile_path,
            key,
            source_facts,
            message,
            source,
        }
    }

    #[test]
    fn plan_is_exact_additive_and_keeps_empty_and_merge_distinct() {
        let fixture = fixture();
        let plan = plan(&fixture.source).unwrap();

        plan.verify_conservation().unwrap();
        assert_eq!(plan.original_facts(), &fixture.source_facts);
        assert_eq!(plan.report().authored_commits, 4);
        assert_eq!(plan.report().authored_empty_commits, 1);
        assert_eq!(plan.report().contentless_merges, 1);
        assert!(plan
            .materialized_facts()
            .iter()
            .any(|fact| fact.e() == &fixture.message));
        assert!(plan.commits().iter().any(|commit| {
            commit.fragment.facts().is_empty() && !commit.fragment.metafacts().is_empty()
        }));
        assert!(plan
            .materialized_facts()
            .iter()
            .any(|fact| fact.a() == &schema::bot_token.id()));
    }

    #[test]
    fn migrated_mutable_rows_remain_inert_beside_native_observations() {
        let fixture = fixture();
        let plan = plan(&fixture.source).unwrap();
        let mut facts = plan.materialized_facts();

        // The historical mutable row is exact retained evidence, not a native
        // immutable observation merely because it carries kind_message.
        assert!(discord::select_messages(&facts, None, None)
            .unwrap()
            .is_empty());

        // A native observation may name the same upstream message without the
        // retained legacy row becoming a second visible version.
        let mut native = Fragment::empty();
        let anchor = discord::message_anchor_fragment("100000000000000001").unwrap();
        let anchor_id = anchor.root().unwrap();
        native += anchor;
        let channel = discord::channel_fragment("100000000000000002").unwrap();
        let channel_id = channel.root().unwrap();
        native += channel;
        let author = discord::user_fragment("100000000000000003").unwrap();
        let author_id = author.root().unwrap();
        native += author;
        native += entity! { _ @
            metadata::tag: archive::kind_message,
            schema::message: anchor_id,
            schema::channel: channel_id,
            archive::author: author_id,
            archive::content: "native Discord content",
            metadata::created_at: at(42.0),
        };
        facts += native.into_facts();

        let selected = discord::select_messages(&facts, None, None).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].anchor, anchor_id);
        assert_ne!(selected[0].observation, fixture.message);
    }

    #[test]
    fn publication_is_idempotent_and_targets_descriptor_handle() {
        let fixture = fixture();
        let plan = plan(&fixture.source).unwrap();

        let first = publish(&fixture.source, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        let after_first = fs::metadata(&fixture.pile).unwrap().len();
        let second = publish(&fixture.source, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(first, second);
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), after_first);

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let team = signer.verifying_key();
        let mut collection = faculties::collection_names::open(pile, DEFAULT_SCOPE_ID, signer);
        assert_eq!(collection.materialize().unwrap(), fixture.source_facts);
        let discovery = discover_target(collection.storage_mut(), DEFAULT_SCOPE_ID, team).unwrap();
        assert_eq!(
            discovery.descriptor().facts(),
            faculties::collection_names::root_descriptor(DEFAULT_SCOPE_ID, team).facts()
        );
        assert_eq!(discovery.commits().len(), plan.commits().len());
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn publication_resumes_after_an_arbitrary_interrupted_prefix() {
        let fixture = fixture();
        let plan = plan(&fixture.source).unwrap();

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection = faculties::collection_names::open(pile, DEFAULT_SCOPE_ID, signer);
        let partial = collection
            .commit(plan.commits()[1].fragment.clone())
            .unwrap();
        collection.into_storage().close().unwrap();

        let resumed = publish(&fixture.source, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(resumed[1], partial);
        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection = faculties::collection_names::open(pile, DEFAULT_SCOPE_ID, signer);
        assert_eq!(collection.materialize().unwrap(), fixture.source_facts);
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn missing_signer_fails_without_growing_the_pile() {
        let fixture = fixture();
        let plan = plan(&fixture.source).unwrap();
        fs::remove_file(&fixture.key).unwrap();
        let before = fs::metadata(&fixture.pile).unwrap().len();

        let error = publish(&fixture.source, &plan, &fixture.pile, Some(&fixture.key)).unwrap_err();
        assert!(format!("{error:#}").contains("load durable signing key"));
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), before);
    }
}
