//! Additive stopped-world projection of the historical `posture` branch.
//!
//! The legacy faculty stored one random-id channel followed by random-id term
//! and exemplar assertions in a linear Repository history.  The collection
//! faculty instead uses intrinsic channels and members plus immutable complete
//! policy revisions. This module proves the old operation shape, republishes
//! every authored fact and exact commit metadata, and adds one canonical
//! intrinsic shadow revision per policy assertion. Original facts are never
//! rewritten or consumed; the target is their set union with those shadows.
//!
//! The reviewed historical branch contains no scan observations.  A scan,
//! fork, contentless merge, duplicate logical policy key, structurally changed
//! text, or unknown attribute is therefore an error rather than an inferred
//! repair. Legacy term case is normalized because the frozen matcher lowercased
//! both terms and candidate text. Legacy exemplar line endings and surrounding
//! file whitespace are normalized to the current identity; the authored
//! embedding that drove matching remains byte-for-byte unchanged.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::attribute::Attribute;
use triblespace::core::blob::encodings::longstring::LongString;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::id::{ExclusiveId, Id};
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::{Inline, InlineEncoding};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::core::trible::{Fragment, TribleSet};
use triblespace::macros::entity;
use triblespace::prelude::{blobencodings, inlineencodings};

use crate::collection_cutover::{
    project_legacy_authored_commits, publish_fragments, FrozenLegacyBranch, FrozenSource,
    LegacyCommitCoordinate, LegacyPinCoordinate, ProjectedLegacyCommit,
};
use crate::schemas::embeddings::{self, Embedding768};
use crate::schemas::posture::{
    self as schema, posture, EXEMPLAR_BENIGN, EXEMPLAR_PROTECTED, KIND_CHANNEL, KIND_EXEMPLAR,
    KIND_POLICY_REVISION, KIND_TERM,
};

const LEGACY_BRANCH_NAME: &str = "posture";

type TextHandle = Inline<Handle<LongString>>;
type EmbeddingHandle = Inline<Handle<Embedding768>>;

/// Conservation census for one complete historical Posture rewrite.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PostureRewriteReport {
    pub authored_commits: usize,
    pub authored_empty_commits: usize,
    pub contentless_merges: usize,
    pub input_fact_occurrences: usize,
    pub input_unique_facts: usize,
    pub legacy_channels: usize,
    pub legacy_terms: usize,
    pub legacy_exemplars: usize,
    pub canonical_channels: usize,
    pub canonical_terms: usize,
    pub canonical_exemplars: usize,
    pub policy_revisions: usize,
    pub canonical_facts: usize,
    pub output_facts: usize,
}

#[cfg(test)]
mod v4_tests {
    use std::fs::{self, File};
    use std::path::PathBuf;

    use ed25519_dalek::SigningKey;
    use triblespace::core::collection::{simplearchive_union, Collection};
    use triblespace::core::inline::encodings::shortstring::ShortString;
    use triblespace::core::repo::Repository;
    use triblespace::macros::{attributes, id_hex};

    use super::*;
    use crate::collection_cutover::{
        discover_target, freeze_source, initialize_signer, load_signer, open_pile_strict,
    };

    attributes! {
        "EA000000000000000000000000000001" unsafe as unexpected_v4: ShortString;
    }

    const METADATA_MARKER_V4: Id = id_hex!("EA000000000000000000000000000002");

    struct Fixture {
        _directory: tempfile::TempDir,
        source: PathBuf,
        destination: PathBuf,
        key: PathBuf,
        branch: Id,
    }

    fn legacy_channel(fragment: &mut Fragment, id: &ExclusiveId, name: &str) {
        let name: TextHandle = fragment.put(name.to_owned());
        *fragment += entity! { id @
            metadata::tag: KIND_CHANNEL,
            posture::channel_name: name,
        };
    }

    fn legacy_term(
        fragment: &mut Fragment,
        id: &ExclusiveId,
        channel: Id,
        text: &str,
        why: Option<&str>,
    ) {
        let text: TextHandle = fragment.put(text.to_owned());
        let why: Option<TextHandle> = why.map(|value| fragment.put(value.to_owned()));
        *fragment += entity! { id @
            metadata::tag: KIND_TERM,
            posture::in_channel: channel,
            posture::term: text,
            posture::why?: why,
        };
    }

    fn legacy_exemplar(fragment: &mut Fragment, id: &ExclusiveId, channel: Id, text: &str) {
        let text: TextHandle = fragment.put(text.to_owned());
        let embedding: EmbeddingHandle = fragment.put(vec![0.0_f32; 768]);
        *fragment += entity! { id @
            metadata::tag: KIND_EXEMPLAR,
            metadata::tag: EXEMPLAR_BENIGN,
            posture::in_channel: channel,
            posture::term: text,
            embeddings::attr::embedding: embedding,
        };
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.pile");
        let destination = directory.path().join("candidate.pile");
        let key = directory.path().join("candidate.key");
        File::create(&source).unwrap();
        File::create(&destination).unwrap();

        let storage = open_pile_strict(&source).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0xE1; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository.create_branch(LEGACY_BRANCH_NAME, None).unwrap();
        let channel = ExclusiveId::force(Id::new([0xE2; 16]).unwrap());

        let mut first = Fragment::empty();
        legacy_channel(&mut first, &channel, "public-release");
        let term = ExclusiveId::force(Id::new([0xE3; 16]).unwrap());
        legacy_term(
            &mut first,
            &term,
            *channel,
            "project-sunrise",
            Some("fixture rationale"),
        );
        let mut workspace = repository.pull(branch).unwrap();
        workspace.commit(first, "first policy assertion");
        repository.push(&mut workspace).unwrap();

        let mut empty = repository.pull(branch).unwrap();
        empty.commit(Fragment::empty(), "authored empty");
        repository.push(&mut empty).unwrap();

        let mut last = Fragment::empty();
        let exemplar = ExclusiveId::force(Id::new([0xE4; 16]).unwrap());
        legacy_exemplar(
            &mut last,
            &exemplar,
            *channel,
            "A sufficiently descriptive benign fixture passage.",
        );
        let mut workspace = repository.pull(branch).unwrap();
        workspace.commit_with_metadata(
            last,
            entity! { metadata::tag: &METADATA_MARKER_V4 },
            "legacy exemplar",
        );
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();
        initialize_signer(&destination, Some(&key)).unwrap();

        Fixture {
            _directory: directory,
            source,
            destination,
            key,
            branch,
        }
    }

    #[test]
    fn additive_plan_conserves_every_fact_and_authored_empty_commit() {
        let fixture = fixture();
        let source = freeze_source(&fixture.source).unwrap();
        let plan = plan(&source).unwrap();
        plan.verify_conservation().unwrap();

        assert_eq!(plan.source_pin().id, fixture.branch);
        assert_eq!(plan.commits().len(), 3);
        assert_eq!(plan.report().authored_empty_commits, 1);
        assert_eq!(plan.report().legacy_channels, 1);
        assert_eq!(plan.report().legacy_terms, 1);
        assert_eq!(plan.report().legacy_exemplars, 1);
        assert_eq!(plan.report().policy_revisions, 2);
        assert_eq!(plan.report().output_facts, plan.materialized_facts().len());
        let materialized = plan.materialized_facts();
        assert!(plan
            .original_facts()
            .iter()
            .all(|fact| materialized.contains(fact)));
    }

    #[test]
    fn complete_union_validator_keeps_legacy_exhaust_inert_and_rejects_malformed_records() {
        let fixture = fixture();
        let source = freeze_source(&fixture.source).unwrap();
        let plan = plan(&source).unwrap();
        let staged = plan
            .commits()
            .iter()
            .fold(Fragment::empty(), |mut staged, commit| {
                staged += commit.fragment.clone();
                staged
            });

        let validated =
            validate_policy_catalog_union(source.reader(), &TribleSet::new(), &staged).unwrap();
        assert_eq!(validated, plan.materialized_facts());
        assert!(plan
            .original_facts()
            .iter()
            .all(|fact| validated.contains(fact)));

        let legacy_term = Id::new([0xE3; 16]).unwrap();
        let mut malformed_legacy = staged.clone();
        malformed_legacy += entity! { ExclusiveId::force_ref(&legacy_term) @
            unexpected_v4: "near-match",
        };
        let error =
            validate_policy_catalog_union(source.reader(), &TribleSet::new(), &malformed_legacy)
                .unwrap_err();
        assert!(format!("{error:#}").contains("unexpected attribute"));

        let materialized = plan.materialized_facts();
        let canonical_term = tagged_entities(&materialized, KIND_TERM)
            .unwrap()
            .into_iter()
            .find(|term| {
                !id_values(&materialized, *term, &posture::role)
                    .unwrap()
                    .is_empty()
            })
            .unwrap();
        let mut malformed_canonical = staged;
        malformed_canonical += entity! { ExclusiveId::force_ref(&canonical_term) @
            posture::role: &EXEMPLAR_BENIGN,
        };
        let error =
            validate_policy_catalog_union(source.reader(), &TribleSet::new(), &malformed_canonical)
                .unwrap_err();
        assert!(format!("{error:#}").contains("expected exactly one"));
    }

    #[test]
    fn publication_targets_v4_descriptor_handle_is_idempotent_and_keeps_source_pin() {
        let fixture = fixture();
        let source = freeze_source(&fixture.source).unwrap();
        let original_pin = source.legacy_pins().to_vec();
        let plan = plan(&source).unwrap();
        let first = publish(&source, &plan, &fixture.destination, Some(&fixture.key)).unwrap();
        assert_eq!(first.len(), 3);
        let after_first = fs::metadata(&fixture.destination).unwrap().len();
        let second = publish(&source, &plan, &fixture.destination, Some(&fixture.key)).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            fs::metadata(&fixture.destination).unwrap().len(),
            after_first
        );

        let signer = load_signer(&fixture.destination, Some(&fixture.key)).unwrap();
        let mut pile = open_pile_strict(&fixture.destination).unwrap();
        let discovery = discover_target(&mut pile, schema::DEFAULT_POLICY_SCOPE_ID).unwrap();
        let expected = simplearchive_union::descriptor(schema::DEFAULT_POLICY_SCOPE_ID);
        assert_eq!(discovery.descriptor().handle(), expected.handle());
        assert_eq!(discovery.commits().len(), 3);
        assert!(discovery
            .commits()
            .iter()
            .all(|commit| commit.collection() == expected.handle()));
        let mut collection = Collection::new(pile, schema::DEFAULT_POLICY_SCOPE_ID, signer);
        assert_eq!(collection.materialize().unwrap(), plan.materialized_facts());
        collection.into_storage().close().unwrap();

        let refreshed = freeze_source(&fixture.source).unwrap();
        assert_eq!(refreshed.legacy_pins(), original_pin.as_slice());
    }

    #[test]
    fn unknown_legacy_shape_is_rejected_instead_of_inferred() {
        let fixture = fixture();
        let storage = open_pile_strict(&fixture.source).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0xE1; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let channel = Id::new([0xE2; 16]).unwrap();
        let mut fragment = Fragment::empty();
        let term = ExclusiveId::force(Id::new([0xE7; 16]).unwrap());
        legacy_term(&mut fragment, &term, channel, "second-term", None);
        fragment += entity! { &term @ unexpected_v4: "near-match" };
        let mut workspace = repository.pull(fixture.branch).unwrap();
        workspace.commit(fragment, "malformed policy assertion");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();

        let source = freeze_source(&fixture.source).unwrap();
        assert!(format!("{:#}", plan(&source).unwrap_err()).contains("unexpected attribute"));
    }

    #[test]
    fn scan_shaped_legacy_history_is_rejected_by_the_reviewed_policy_transform() {
        let fixture = fixture();
        let storage = open_pile_strict(&fixture.source).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0xE1; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let mut fragment = Fragment::empty();
        fragment += entity! { metadata::tag: schema::KIND_SCAN };
        let mut workspace = repository.pull(fixture.branch).unwrap();
        workspace.commit(fragment, "unreviewed scan shape");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();

        let source = freeze_source(&fixture.source).unwrap();
        assert!(format!("{:#}", plan(&source).unwrap_err()).contains("unrecognized tag set"));
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostureMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostureMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<PostureMigrationCommit>,
    original: TribleSet,
    canonical: TribleSet,
    report: PostureRewriteReport,
}

impl PostureMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[PostureMigrationCommit] {
        &self.commits
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.original
    }

    pub fn canonical_facts(&self) -> &TribleSet {
        &self.canonical
    }

    pub const fn report(&self) -> &PostureRewriteReport {
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
            bail!("planned Posture policy is not original facts union canonical shadows");
        }
        Ok(())
    }

    fn validate(&self, reader: &PileReader) -> Result<()> {
        self.verify_conservation()?;
        let mut staged = Fragment::empty();
        for commit in &self.commits {
            staged += commit.fragment.clone();
        }
        let validated = validate_policy_catalog_union(reader, &TribleSet::new(), &staged)
            .context("validate complete additive Posture migration")?;
        if validated != self.materialized_facts() {
            bail!("planned Posture fragment union changed during validation");
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct LegacyChannel {
    old_id: Id,
    name: String,
}

#[derive(Clone, Debug)]
enum LegacyMember {
    Term {
        old_channel: Id,
        text: String,
        why: Option<String>,
    },
    Exemplar {
        old_channel: Id,
        text: String,
        role: Id,
        embedding: Vec<f32>,
    },
}

#[derive(Clone, Debug)]
struct LegacyOperation {
    channel: Option<LegacyChannel>,
    member: LegacyMember,
}

#[derive(Clone, Debug)]
struct ChannelState {
    name: String,
    canonical_id: Id,
    members: BTreeSet<Id>,
    head: Option<Id>,
    term_keys: BTreeSet<String>,
    exemplar_keys: BTreeSet<String>,
}

/// Plan the complete named legacy Posture branch without mutating its pile.
///
/// The reviewed historical branch is a linear sequence of policy assertions
/// and contains no scans. Any fork, merge, scan-shaped entity, unknown field,
/// or duplicate logical policy key fails closed instead of being repaired by
/// guesswork.
pub fn plan(source: &FrozenSource) -> Result<PostureMigrationPlan> {
    let branch = source
        .legacy_branch(LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Posture branch"))?;
    require_linear_history(&branch)?;
    let mut projected =
        project_legacy_authored_commits(source, &branch, validate_legacy_known_payloads)
            .context("project frozen Posture authored commits")?;
    projected.sort_unstable_by_key(|commit| commit.source);
    rewrite_posture_authored_commits(&branch, projected, source.reader())
}

fn rewrite_posture_authored_commits(
    branch: &FrozenLegacyBranch,
    projected: Vec<ProjectedLegacyCommit>,
    reader: &PileReader,
) -> Result<PostureMigrationPlan> {
    require_linear_history(branch)?;

    let mut by_commit = projected
        .into_iter()
        .map(|commit| (commit.source.commit.raw, commit))
        .collect::<BTreeMap<_, _>>();

    let mut old_channels = BTreeMap::<Id, ChannelState>::new();
    let mut canonical = Fragment::empty();
    let mut output = Vec::new();
    let mut original = TribleSet::new();
    let mut report = PostureRewriteReport {
        authored_commits: by_commit.len(),
        contentless_merges: branch
            .deltas
            .iter()
            .filter(|delta| !delta.is_authored())
            .count(),
        ..PostureRewriteReport::default()
    };

    for delta in &branch.deltas {
        let Some(projected) = by_commit.remove(&delta.commit.raw) else {
            bail!(
                "legacy Posture commit {} did not project to an authored commit",
                hex::encode_upper(delta.commit.raw)
            );
        };
        report.input_fact_occurrences += projected.content.facts().len();
        original += projected.content.facts().clone();

        if projected.content.facts().is_empty() {
            report.authored_empty_commits += 1;
            let mut fragment = projected.content;
            fragment.describe_with(projected.metadata);
            output.push(PostureMigrationCommit {
                source: projected.source,
                fragment,
            });
            continue;
        }

        let operation =
            parse_legacy_operation(reader, projected.content.facts()).with_context(|| {
                format!(
                    "validate legacy Posture operation {}",
                    hex::encode_upper(delta.commit.raw)
                )
            })?;

        if let Some(channel) = operation.channel {
            if old_channels.contains_key(&channel.old_id) {
                bail!(
                    "legacy Posture channel {:X} is asserted more than once",
                    channel.old_id
                );
            }
            let mut identity = Fragment::empty();
            let canonical_id = append_channel(&mut identity, &channel.name);
            old_channels.insert(
                channel.old_id,
                ChannelState {
                    name: channel.name,
                    canonical_id,
                    members: BTreeSet::new(),
                    head: None,
                    term_keys: BTreeSet::new(),
                    exemplar_keys: BTreeSet::new(),
                },
            );
            report.legacy_channels += 1;
        }

        let old_channel = match &operation.member {
            LegacyMember::Term { old_channel, .. } | LegacyMember::Exemplar { old_channel, .. } => {
                *old_channel
            }
        };
        let state = old_channels.get_mut(&old_channel).ok_or_else(|| {
            anyhow!("legacy Posture member references channel {old_channel:X} before its assertion")
        })?;

        let mut shadows = Fragment::empty();
        let channel = append_channel(&mut shadows, &state.name);
        if channel != state.canonical_id {
            bail!("canonical Posture channel identity changed during rewrite");
        }

        let member = match operation.member {
            LegacyMember::Term { text, why, .. } => {
                if !state.term_keys.insert(text.clone()) {
                    bail!("legacy Posture policy repeats canonical term in channel {channel:X}");
                }
                report.legacy_terms += 1;
                append_term(&mut shadows, channel, &text, why.as_deref())
            }
            LegacyMember::Exemplar {
                text,
                role,
                embedding,
                ..
            } => {
                if !state.exemplar_keys.insert(text.clone()) {
                    bail!(
                        "legacy Posture policy repeats canonical exemplar in channel {channel:X}"
                    );
                }
                report.legacy_exemplars += 1;
                append_exemplar(&mut shadows, channel, &text, role, embedding)
            }
        };
        state.members.insert(member);
        let predecessors = state.head.into_iter().collect();
        state.head = Some(append_policy_revision(
            &mut shadows,
            channel,
            &state.members,
            &predecessors,
        ));
        report.policy_revisions += 1;

        canonical += shadows.clone();
        let mut fragment = projected.content;
        fragment += shadows;
        fragment.describe_with(projected.metadata);
        output.push(PostureMigrationCommit {
            source: projected.source,
            fragment,
        });
    }

    if !by_commit.is_empty() {
        bail!("projected Posture commits contain commits outside the frozen branch");
    }

    report.input_unique_facts = original.len();
    report.canonical_channels = old_channels.len();
    report.canonical_terms = report.legacy_terms;
    report.canonical_exemplars = report.legacy_exemplars;
    report.canonical_facts = canonical.facts().len();
    let mut materialized = TribleSet::new();
    for commit in &output {
        materialized += commit.fragment.facts().clone();
    }
    report.output_facts = materialized.len();

    let plan = PostureMigrationPlan {
        source_pin: branch.pin_coordinate(),
        commits: output,
        original,
        canonical: canonical.into_facts(),
        report,
    };
    plan.validate(reader)?;
    Ok(plan)
}

/// Publish a verified plan through the native descriptor-handle collection.
/// Every legacy Posture writer must remain stopped from [`FrozenSource`]
/// creation through publication. Exact replay is idempotent; the source pin is
/// read-only and remains unchanged.
pub fn publish(
    source: &FrozenSource,
    plan: &PostureMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Posture migration plan does not belong to this frozen source");
    }
    plan.validate(source.reader())?;
    publish_fragments(
        target,
        key,
        schema::DEFAULT_POLICY_SCOPE_ID,
        plan.commits.iter().map(|commit| commit.fragment.clone()),
    )
}

fn require_linear_history(branch: &FrozenLegacyBranch) -> Result<()> {
    let mut previous = None;
    for delta in &branch.deltas {
        let expected = previous.into_iter().collect::<Vec<_>>();
        if delta.parents != expected {
            bail!(
                "legacy Posture history is not the reviewed linear authored sequence at commit {}",
                hex::encode_upper(delta.commit.raw)
            );
        }
        if !delta.is_authored() {
            bail!(
                "legacy Posture history contains an unreviewed contentless merge {}",
                hex::encode_upper(delta.commit.raw)
            );
        }
        previous = Some(delta.commit);
    }
    Ok(())
}

fn parse_legacy_operation(reader: &PileReader, facts: &TribleSet) -> Result<LegacyOperation> {
    validate_legacy_known_payloads(reader, facts)?;
    let entities = facts.iter().map(|fact| *fact.e()).collect::<BTreeSet<_>>();
    let mut channel = None;
    let mut member = None;

    for entity in entities {
        let tags = id_values(facts, entity, &metadata::tag)?;
        let tags = tags.into_iter().collect::<BTreeSet<_>>();
        if tags == BTreeSet::from([KIND_CHANNEL]) {
            require_attributes(
                facts,
                entity,
                [metadata::tag.id(), posture::channel_name.id()],
                "legacy channel",
            )?;
            let name = read_text(
                reader,
                exactly_one(
                    inline_values(facts, entity, &posture::channel_name),
                    entity,
                    "legacy channel name",
                )?,
                "legacy channel name",
            )?;
            require_canonical_channel(&name)?;
            if channel
                .replace(LegacyChannel {
                    old_id: entity,
                    name,
                })
                .is_some()
            {
                bail!("one legacy Posture operation asserts multiple channels");
            }
            continue;
        }

        if tags == BTreeSet::from([KIND_TERM]) {
            require_attributes(
                facts,
                entity,
                [
                    metadata::tag.id(),
                    posture::term.id(),
                    posture::in_channel.id(),
                    posture::why.id(),
                ],
                "legacy term",
            )?;
            let old_channel = exactly_one(
                id_values(facts, entity, &posture::in_channel)?,
                entity,
                "legacy term channel",
            )?;
            let text = read_text(
                reader,
                exactly_one(
                    inline_values(facts, entity, &posture::term),
                    entity,
                    "legacy term text",
                )?,
                "legacy term text",
            )?;
            let text = canonicalize_legacy_term(&text)?;
            let why = at_most_one(
                inline_values(facts, entity, &posture::why),
                entity,
                "legacy term rationale",
            )?
            .map(|handle| read_text(reader, handle, "legacy term rationale"))
            .transpose()?;
            if why
                .as_ref()
                .is_some_and(|why| why.is_empty() || why.trim() != why)
            {
                bail!("legacy term {entity:X} has a non-canonical rationale");
            }
            if member
                .replace(LegacyMember::Term {
                    old_channel,
                    text,
                    why,
                })
                .is_some()
            {
                bail!("one legacy Posture operation asserts multiple policy members");
            }
            continue;
        }

        let protected_tags = BTreeSet::from([KIND_EXEMPLAR]);
        let benign_tags = BTreeSet::from([KIND_EXEMPLAR, EXEMPLAR_BENIGN]);
        if tags == protected_tags || tags == benign_tags {
            require_attributes(
                facts,
                entity,
                [
                    metadata::tag.id(),
                    posture::term.id(),
                    posture::in_channel.id(),
                    embeddings::attr::embedding.id(),
                ],
                "legacy exemplar",
            )?;
            let old_channel = exactly_one(
                id_values(facts, entity, &posture::in_channel)?,
                entity,
                "legacy exemplar channel",
            )?;
            let text = read_text(
                reader,
                exactly_one(
                    inline_values(facts, entity, &posture::term),
                    entity,
                    "legacy exemplar text",
                )?,
                "legacy exemplar text",
            )?;
            let text = canonicalize_legacy_exemplar(&text)?;
            let handle = exactly_one(
                inline_values(facts, entity, &embeddings::attr::embedding),
                entity,
                "legacy exemplar embedding",
            )?;
            let embedding: View<[f32]> = reader
                .get(handle)
                .with_context(|| format!("read legacy Posture exemplar embedding on {entity:X}"))?;
            let role = if tags == benign_tags {
                EXEMPLAR_BENIGN
            } else {
                EXEMPLAR_PROTECTED
            };
            if member
                .replace(LegacyMember::Exemplar {
                    old_channel,
                    text,
                    role,
                    embedding: embedding.to_vec(),
                })
                .is_some()
            {
                bail!("one legacy Posture operation asserts multiple policy members");
            }
            continue;
        }

        bail!(
            "legacy Posture entity {entity:X} has an unrecognized tag set ({})",
            tags.iter()
                .map(|tag| format!("{tag:X}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    Ok(LegacyOperation {
        channel,
        member: member.ok_or_else(|| anyhow!("legacy Posture operation has no policy member"))?,
    })
}

fn append_channel(fragment: &mut Fragment, name: &str) -> Id {
    let name: TextHandle = fragment.put(name.to_owned());
    let channel = entity! {
        metadata::tag: KIND_CHANNEL,
        posture::channel_name: name,
    };
    let id = channel.root().expect("intrinsic channel has one root");
    *fragment += channel;
    id
}

fn append_term(fragment: &mut Fragment, channel: Id, text: &str, why: Option<&str>) -> Id {
    let text: TextHandle = fragment.put(text.to_owned());
    let why: Option<TextHandle> = why.map(|value| fragment.put(value.to_owned()));
    let term = entity! {
        metadata::tag: KIND_TERM,
        posture::in_channel: channel,
        posture::term: text,
        posture::role: EXEMPLAR_PROTECTED,
        posture::why?: why,
    };
    let id = term.root().expect("intrinsic term has one root");
    *fragment += term;
    id
}

fn append_exemplar(
    fragment: &mut Fragment,
    channel: Id,
    text: &str,
    role: Id,
    embedding: Vec<f32>,
) -> Id {
    let text: TextHandle = fragment.put(text.to_owned());
    let exemplar = entity! {
        metadata::tag: KIND_EXEMPLAR,
        posture::in_channel: channel,
        posture::term: text,
        posture::role: role,
    };
    let id = exemplar.root().expect("intrinsic exemplar has one root");
    *fragment += exemplar;
    let embedding: EmbeddingHandle = fragment.put(embedding);
    *fragment += entity! {
        ExclusiveId::force_ref(&id) @ embeddings::attr::embedding: embedding,
    };
    id
}

fn append_policy_revision(
    fragment: &mut Fragment,
    channel: Id,
    members: &BTreeSet<Id>,
    predecessors: &BTreeSet<Id>,
) -> Id {
    let revision = entity! {
        metadata::tag: KIND_POLICY_REVISION,
        posture::in_channel: channel,
        posture::policy_member*: members.clone(),
        metadata::supersedes*: predecessors.clone(),
    };
    let id = revision
        .root()
        .expect("intrinsic policy revision has one root");
    *fragment += revision;
    id
}

fn validate_legacy_known_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts {
        if [
            posture::channel_name.id(),
            posture::term.id(),
            posture::why.id(),
            posture::path.id(),
            posture::locator.id(),
            posture::value.id(),
            posture::target.id(),
            posture::detail.id(),
        ]
        .contains(fact.a())
        {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::LongString>>();
            let _: View<str> = reader.get(handle).with_context(|| {
                format!(
                    "read legacy Posture text payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        } else if fact.a() == &embeddings::attr::embedding.id() {
            let handle = *fact.v::<inlineencodings::Handle<Embedding768>>();
            let _: View<[f32]> = reader.get(handle).with_context(|| {
                format!(
                    "read legacy Posture embedding {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

/// Validate the complete collection-native Posture policy catalog.
pub fn validate_policy_catalog(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    validate_policy_catalog_with::<PileReader>(reader, None, facts)
}

/// Validate the exact additive policy union a native publication would create.
///
/// Preserved legacy entities remain validated evidence but do not enter the
/// canonical policy state. Payloads introduced by `fragment` are read through
/// its in-memory blob overlay before any bytes reach the pile.
pub fn validate_policy_catalog_union(
    reader: &PileReader,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<TribleSet> {
    let mut union = current.clone();
    union += fragment.facts().clone();
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .reader()
        .context("snapshot staged Posture policy payloads")?;
    validate_policy_catalog_with(reader, Some(&overlay), &union)?;
    Ok(union)
}

fn validate_policy_catalog_with<R>(
    reader: &PileReader,
    staged: Option<&R>,
    facts: &TribleSet,
) -> Result<()>
where
    R: BlobStoreGet + BlobStoreMeta,
{
    validate_known_payloads_with(reader, staged, facts)?;
    let tagged_channels = tagged_entities(facts, KIND_CHANNEL)?;
    let tagged_terms = tagged_entities(facts, KIND_TERM)?;
    let tagged_exemplars = tagged_entities(facts, KIND_EXEMPLAR)?;
    let revisions = tagged_entities(facts, KIND_POLICY_REVISION)?;
    let mut known = tagged_channels.clone();
    known.extend(tagged_terms.iter().copied());
    known.extend(tagged_exemplars.iter().copied());
    known.extend(revisions.iter().copied());
    let actual = facts.iter().map(|fact| *fact.e()).collect::<BTreeSet<_>>();
    if actual != known {
        let unknown = actual.difference(&known).copied().collect::<Vec<_>>();
        bail!(
            "Posture policy collection contains {} unrecognized entity/entities ({})",
            unknown.len(),
            unknown
                .iter()
                .map(|entity| format!("{entity:X}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Legacy and native channels share the same shape and tag. Intrinsic
    // identity is the semantic boundary: random-id legacy channels remain
    // validated evidence, while only intrinsic channels may anchor revisions.
    let mut channels = BTreeSet::new();
    for channel in &tagged_channels {
        require_attributes(
            facts,
            *channel,
            [metadata::tag.id(), posture::channel_name.id()],
            "channel",
        )?;
        require_tags(facts, *channel, BTreeSet::from([KIND_CHANNEL]), "channel")?;
        let name = exactly_one(
            inline_values(facts, *channel, &posture::channel_name),
            *channel,
            "channel name",
        )?;
        let body = read_text_with(reader, staged, name, "channel name")?;
        require_canonical_channel(&body)?;
        let expected = entity! {
            metadata::tag: KIND_CHANNEL,
            posture::channel_name: name,
        }
        .root()
        .expect("channel root");
        if expected == *channel {
            channels.insert(*channel);
        }
    }

    let mut member_channels = BTreeMap::new();
    let mut term_keys = BTreeMap::new();
    for term in &tagged_terms {
        // Historical terms have no explicit role and retain their random ids.
        // Validate their exact reviewed shape, but do not admit them into a
        // canonical policy revision.
        if !entity_attributes(facts, *term).contains(&posture::role.id()) {
            require_attributes(
                facts,
                *term,
                [
                    metadata::tag.id(),
                    posture::in_channel.id(),
                    posture::term.id(),
                    posture::why.id(),
                ],
                "legacy term",
            )?;
            require_tags(facts, *term, BTreeSet::from([KIND_TERM]), "legacy term")?;
            let channel = exactly_one(
                id_values(facts, *term, &posture::in_channel)?,
                *term,
                "legacy term channel",
            )?;
            if !tagged_channels.contains(&channel) {
                bail!("Posture legacy term {term:X} references missing channel {channel:X}");
            }
            let text = exactly_one(
                inline_values(facts, *term, &posture::term),
                *term,
                "legacy term text",
            )?;
            let body = read_text_with(reader, staged, text, "legacy term text")?;
            if body.is_empty() || body.trim() != body {
                bail!("Posture legacy term {term:X} has malformed text");
            }
            let why = at_most_one(
                inline_values(facts, *term, &posture::why),
                *term,
                "legacy term rationale",
            )?;
            if let Some(why) = why {
                let body = read_text_with(reader, staged, why, "legacy term rationale")?;
                if body.is_empty() || body.trim() != body {
                    bail!("Posture legacy term {term:X} has a non-canonical rationale");
                }
            }
            continue;
        }

        require_attributes(
            facts,
            *term,
            [
                metadata::tag.id(),
                posture::in_channel.id(),
                posture::term.id(),
                posture::role.id(),
                posture::why.id(),
            ],
            "term",
        )?;
        require_tags(facts, *term, BTreeSet::from([KIND_TERM]), "term")?;
        let channel = exactly_one(
            id_values(facts, *term, &posture::in_channel)?,
            *term,
            "term channel",
        )?;
        if !channels.contains(&channel) {
            bail!("Posture term {term:X} references missing channel {channel:X}");
        }
        let text = exactly_one(
            inline_values(facts, *term, &posture::term),
            *term,
            "term text",
        )?;
        let key = read_text_with(reader, staged, text, "term text")?;
        require_canonical_term(&key)?;
        let role = exactly_one(id_values(facts, *term, &posture::role)?, *term, "term role")?;
        if role != EXEMPLAR_PROTECTED {
            bail!("Posture term {term:X} is not explicitly protected");
        }
        let why = at_most_one(
            inline_values(facts, *term, &posture::why),
            *term,
            "term rationale",
        )?;
        if let Some(why) = why {
            let body = read_text_with(reader, staged, why, "term rationale")?;
            if body.is_empty() || body.trim() != body {
                bail!("Posture term {term:X} has a non-canonical rationale");
            }
        }
        let expected = entity! {
            metadata::tag: KIND_TERM,
            posture::in_channel: channel,
            posture::term: text,
            posture::role: role,
            posture::why?: why,
        }
        .root()
        .expect("term root");
        if expected != *term {
            bail!("Posture term {term:X} is not intrinsic");
        }
        member_channels.insert(*term, channel);
        term_keys.insert(*term, key);
    }

    let mut exemplar_keys = BTreeMap::new();
    for exemplar in &tagged_exemplars {
        // Historical exemplars likewise have no explicit role. Their old
        // protected/benign tag convention and embedding remain validated
        // evidence, but only role-bearing intrinsic exemplars are live.
        if !entity_attributes(facts, *exemplar).contains(&posture::role.id()) {
            require_attributes(
                facts,
                *exemplar,
                [
                    metadata::tag.id(),
                    posture::in_channel.id(),
                    posture::term.id(),
                    embeddings::attr::embedding.id(),
                ],
                "legacy exemplar",
            )?;
            let tags = id_values(facts, *exemplar, &metadata::tag)?
                .into_iter()
                .collect::<BTreeSet<_>>();
            if tags != BTreeSet::from([KIND_EXEMPLAR])
                && tags != BTreeSet::from([KIND_EXEMPLAR, EXEMPLAR_BENIGN])
            {
                bail!("Posture legacy exemplar {exemplar:X} has invalid tags");
            }
            let channel = exactly_one(
                id_values(facts, *exemplar, &posture::in_channel)?,
                *exemplar,
                "legacy exemplar channel",
            )?;
            if !tagged_channels.contains(&channel) {
                bail!(
                    "Posture legacy exemplar {exemplar:X} references missing channel {channel:X}"
                );
            }
            let text = exactly_one(
                inline_values(facts, *exemplar, &posture::term),
                *exemplar,
                "legacy exemplar text",
            )?;
            let body = read_text_with(reader, staged, text, "legacy exemplar text")?;
            canonicalize_legacy_exemplar(&body)?;
            if inline_values(facts, *exemplar, &embeddings::attr::embedding).is_empty() {
                bail!("Posture legacy exemplar {exemplar:X} has no embedding exhaust");
            }
            continue;
        }

        require_attributes(
            facts,
            *exemplar,
            [
                metadata::tag.id(),
                posture::in_channel.id(),
                posture::term.id(),
                posture::role.id(),
                embeddings::attr::embedding.id(),
            ],
            "exemplar",
        )?;
        require_tags(
            facts,
            *exemplar,
            BTreeSet::from([KIND_EXEMPLAR]),
            "exemplar",
        )?;
        let channel = exactly_one(
            id_values(facts, *exemplar, &posture::in_channel)?,
            *exemplar,
            "exemplar channel",
        )?;
        if !channels.contains(&channel) {
            bail!("Posture exemplar {exemplar:X} references missing channel {channel:X}");
        }
        let text = exactly_one(
            inline_values(facts, *exemplar, &posture::term),
            *exemplar,
            "exemplar text",
        )?;
        let key = read_text_with(reader, staged, text, "exemplar text")?;
        require_canonical_exemplar(&key)?;
        let role = exactly_one(
            id_values(facts, *exemplar, &posture::role)?,
            *exemplar,
            "exemplar role",
        )?;
        if role != EXEMPLAR_PROTECTED && role != EXEMPLAR_BENIGN {
            bail!("Posture exemplar {exemplar:X} has an invalid role");
        }
        let expected = entity! {
            metadata::tag: KIND_EXEMPLAR,
            posture::in_channel: channel,
            posture::term: text,
            posture::role: role,
        }
        .root()
        .expect("exemplar root");
        if expected != *exemplar {
            bail!("Posture exemplar {exemplar:X} is not intrinsic");
        }
        member_channels.insert(*exemplar, channel);
        exemplar_keys.insert(*exemplar, key);
    }

    for revision in &revisions {
        require_attributes(
            facts,
            *revision,
            [
                metadata::tag.id(),
                posture::in_channel.id(),
                posture::policy_member.id(),
                metadata::supersedes.id(),
            ],
            "policy revision",
        )?;
        require_tags(
            facts,
            *revision,
            BTreeSet::from([KIND_POLICY_REVISION]),
            "policy revision",
        )?;
        let channel = exactly_one(
            id_values(facts, *revision, &posture::in_channel)?,
            *revision,
            "policy revision channel",
        )?;
        if !channels.contains(&channel) {
            bail!("Posture revision {revision:X} references missing channel {channel:X}");
        }
        let members = id_values(facts, *revision, &posture::policy_member)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut revision_term_keys = BTreeMap::<String, Id>::new();
        let mut revision_exemplar_keys = BTreeMap::<String, Id>::new();
        for member in &members {
            if member_channels.get(member) != Some(&channel) {
                bail!(
                    "Posture revision {revision:X} references missing or cross-channel member {member:X}"
                );
            }
            if let Some(key) = term_keys.get(member) {
                if let Some(other) = revision_term_keys.insert(key.clone(), *member) {
                    bail!(
                        "Posture revision {revision:X} contains two identities for canonical term {key:?} ({other:X}, {member:X})"
                    );
                }
            } else if let Some(key) = exemplar_keys.get(member) {
                if let Some(other) = revision_exemplar_keys.insert(key.clone(), *member) {
                    bail!(
                        "Posture revision {revision:X} contains two identities for canonical exemplar {key:?} ({other:X}, {member:X})"
                    );
                }
            } else {
                bail!("Posture revision {revision:X} references unknown member {member:X}");
            }
        }
        let predecessors = id_values(facts, *revision, &metadata::supersedes)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        for predecessor in &predecessors {
            if predecessor == revision || !revisions.contains(predecessor) {
                bail!("Posture revision {revision:X} has invalid predecessor {predecessor:X}");
            }
            let predecessor_channel = exactly_one(
                id_values(facts, *predecessor, &posture::in_channel)?,
                *predecessor,
                "predecessor channel",
            )?;
            if predecessor_channel != channel {
                bail!("Posture revision {revision:X} crosses channel histories");
            }
        }
        let expected = entity! {
            metadata::tag: KIND_POLICY_REVISION,
            posture::in_channel: channel,
            posture::policy_member*: members,
            metadata::supersedes*: predecessors,
        }
        .root()
        .expect("policy revision root");
        if expected != *revision {
            bail!("Posture revision {revision:X} is not intrinsic");
        }
    }

    Ok(())
}

fn tagged_entities(facts: &TribleSet, tag: Id) -> Result<BTreeSet<Id>> {
    let mut entities = BTreeSet::new();
    for entity in facts.iter().map(|fact| *fact.e()).collect::<BTreeSet<_>>() {
        if id_values(facts, entity, &metadata::tag)?.contains(&tag) {
            entities.insert(entity);
        }
    }
    Ok(entities)
}

fn require_tags(facts: &TribleSet, entity: Id, expected: BTreeSet<Id>, kind: &str) -> Result<()> {
    let actual = id_values(facts, entity, &metadata::tag)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual != expected {
        bail!("Posture {kind} {entity:X} has invalid tags");
    }
    Ok(())
}

fn entity_attributes(facts: &TribleSet, entity: Id) -> BTreeSet<Id> {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity)
        .map(|fact| *fact.a())
        .collect()
}

fn require_attributes(
    facts: &TribleSet,
    entity: Id,
    allowed: impl IntoIterator<Item = Id>,
    kind: &str,
) -> Result<()> {
    let actual = entity_attributes(facts, entity);
    let allowed = allowed.into_iter().collect::<BTreeSet<_>>();
    if !actual.is_subset(&allowed) {
        bail!("Posture {kind} {entity:X} has an unexpected attribute");
    }
    Ok(())
}

fn inline_values<V: InlineEncoding>(
    facts: &TribleSet,
    entity: Id,
    attribute: &Attribute<V>,
) -> Vec<Inline<V>> {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity && fact.a() == &attribute.id())
        .map(|fact| *fact.v::<V>())
        .collect()
}

fn id_values(
    facts: &TribleSet,
    entity: Id,
    attribute: &Attribute<inlineencodings::GenId>,
) -> Result<Vec<Id>> {
    inline_values(facts, entity, attribute)
        .into_iter()
        .map(|value| {
            value
                .try_from_inline()
                .map_err(|error| anyhow!("decode Posture id on {entity:X}: {error:?}"))
        })
        .collect()
}

fn exactly_one<T>(mut values: Vec<T>, entity: Id, field: &str) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "Posture entity {entity:X} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(values.pop().expect("length checked"))
}

fn at_most_one<T>(mut values: Vec<T>, entity: Id, field: &str) -> Result<Option<T>> {
    if values.len() > 1 {
        bail!(
            "Posture entity {entity:X} has {} values for {field}; expected at most one",
            values.len()
        );
    }
    Ok(values.pop())
}

fn read_text(reader: &PileReader, handle: TextHandle, field: &str) -> Result<String> {
    let value: View<str> = reader
        .get(handle)
        .with_context(|| format!("read Posture {field} {}", hex::encode_upper(handle.raw)))?;
    Ok(value.to_string())
}

fn read_text_with<R>(
    reader: &PileReader,
    staged: Option<&R>,
    handle: TextHandle,
    field: &str,
) -> Result<String>
where
    R: BlobStoreGet + BlobStoreMeta,
{
    if let Some(staged) = staged {
        if staged
            .metadata(handle)
            .with_context(|| format!("inspect staged Posture {field} payload"))?
            .is_some()
        {
            let value: View<str> = staged
                .get(handle)
                .with_context(|| format!("decode staged Posture {field} payload"))?;
            return Ok(value.to_string());
        }
    }
    read_text(reader, handle, field)
}

fn validate_known_payloads_with<R>(
    reader: &PileReader,
    staged: Option<&R>,
    facts: &TribleSet,
) -> Result<()>
where
    R: BlobStoreGet + BlobStoreMeta,
{
    for fact in facts {
        if [
            posture::channel_name.id(),
            posture::term.id(),
            posture::why.id(),
            posture::path.id(),
            posture::locator.id(),
            posture::value.id(),
            posture::target.id(),
            posture::detail.id(),
        ]
        .contains(fact.a())
        {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::LongString>>();
            read_text_with(reader, staged, handle, "text").with_context(|| {
                format!(
                    "read Posture text payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        } else if fact.a() == &embeddings::attr::embedding.id() {
            let handle = *fact.v::<inlineencodings::Handle<Embedding768>>();
            if let Some(staged) = staged {
                if staged
                    .metadata(handle)
                    .context("inspect staged Posture embedding")?
                    .is_some()
                {
                    let _: View<[f32]> = staged
                        .get(handle)
                        .context("decode staged Posture embedding")?;
                    continue;
                }
            }
            let _: View<[f32]> = reader.get(handle).with_context(|| {
                format!(
                    "read existing Posture embedding {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

fn require_canonical_channel(value: &str) -> Result<()> {
    let canonical = value.trim().to_lowercase();
    if canonical.is_empty() || canonical != value {
        bail!("Posture channel name is not canonical");
    }
    Ok(())
}

/// Preserve the frozen lexical matcher's exact case-insensitive semantics
/// while rejecting whitespace changes that the old matcher did not erase.
fn canonicalize_legacy_term(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("legacy Posture term text is empty");
    }
    if trimmed != value {
        bail!("legacy Posture term text has surrounding whitespace");
    }
    Ok(value.to_lowercase())
}

fn require_canonical_term(value: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("Posture term text is empty");
    }
    if trimmed != value {
        bail!("Posture term text has non-canonical surrounding whitespace");
    }
    if trimmed.to_lowercase() != value {
        bail!("Posture term text has non-canonical case");
    }
    Ok(())
}

fn canonicalize_legacy_exemplar(value: &str) -> Result<String> {
    let canonical = value
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .trim()
        .to_owned();
    if canonical.is_empty() {
        bail!("legacy Posture exemplar text is empty");
    }
    Ok(canonical)
}

fn require_canonical_exemplar(value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("Posture exemplar text is empty");
    }
    let normalized_newlines = value.replace("\r\n", "\n").replace('\r', "\n");
    if normalized_newlines != value {
        bail!("Posture exemplar text has non-canonical line endings");
    }
    if value.trim() != value {
        bail!("Posture exemplar text has surrounding whitespace");
    }
    Ok(())
}
