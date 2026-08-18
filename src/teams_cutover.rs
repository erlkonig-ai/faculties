//! Sanitizing stopped-world migration of the legacy Teams branch.
//!
//! Historical Teams facts are evidence. The migration therefore changes only
//! their storage authority: every authored Repository commit becomes one
//! independently signed native collection commit, while contentless merge
//! nodes remain verified ancestry. Legacy OAuth rows are a bounded retired
//! partition: they are validated as source evidence but neither their facts
//! nor their plaintext payload blobs are republished into native Teams
//! authority. Live authentication begins at source-scoped auth profiles which
//! reference exact encrypted shared-Secrets versions.

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::blob::encodings::UnknownBlob;
use triblespace::core::blob::{Blob, Bytes};
use triblespace::core::collection::{Collection, CollectionCommit};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet};
use triblespace::macros::{attributes, id_hex};
use triblespace::prelude::blobencodings::{LongString, RawBytes, WasmCode};
use triblespace::prelude::inlineencodings::{GenId, Handle, NsTAIInterval, ShortString};
use triblespace::prelude::*;

use crate::collection_cutover::{
    load_signer, open_pile_strict, project_legacy_authored_commits, FrozenSource,
    LegacyCommitCoordinate, LegacyPinCoordinate,
};
use crate::schemas::archive::archive;
use crate::schemas::files::file;
use crate::schemas::teams::{teams, DEFAULT_SCOPE_ID};
use crate::teams as capability;

use crate::schemas::teams::LEGACY_BRANCH_NAME;

mod legacy {
    use super::*;

    attributes! {
        // Protocol-local entity kinds preceded the shared `metadata::tag`.
        "5F10520477A04E5FB322C85CC78C6762" unsafe as pub local_kind: GenId;
        // These two creation-time attributes straddle the historical inline
        // time-encoding migration. Their rows were later supplemented with
        // canonical `metadata::created_at` facts rather than rewritten.
        "0DA5DD275AA34F86B0297CC35F1B7395" unsafe as pub created_at_le: NsTAIInterval;
        "59FA7C04A43B96F31414D1B4544FAEC2" unsafe as pub created_at_ordered: NsTAIInterval;
        // Teams published this expiry attribute before the April 2026
        // timestamp migration moved new writes to `metadata::expires_at`.
        "706CC590BF4684CA8FA00E4123C43124" unsafe as pub expires_at: NsTAIInterval;
        "57AABA4FBA3A5EC6EF28DC80CD6E0919" unsafe as pub delta_link: Handle<LongString>;
        "438A29922F91F873A69C3856AA7A553F" unsafe as pub access_token: Handle<LongString>;
        "60C85DD37D09D3D27BC6BFA0E8040EA9" unsafe as pub refresh_token: Handle<LongString>;
        "0F7784BBDA2EE5B9009DE688472D6F24" unsafe as pub token_type: Handle<LongString>;
        "139B46989D7F56C7DFE6259FD74479AC" unsafe as pub scope: Handle<LongString>;
        "34ACCCECE281E1A0E191EEEBE7E47A23" unsafe as pub tenant: Handle<LongString>;
        "8C6CA6A45DCA9F78420BC216A83F4C22" unsafe as pub client_id: Handle<LongString>;
        "0E734F66EBBA45ED022D1EE539B11EBE" unsafe as pub client_secret: Handle<LongString>;
        "B0D18159D6035C576AE6B5D871AB4D63" unsafe as pub attachment_data: Handle<RawBytes>;
        "EEFDB32D37B7B2834D99ACCF159B6507" unsafe as pub attachment_mime: ShortString;
    }

    pub const KIND_TOKEN: Id = id_hex!("7B6DBE9FD29182D97F1699437CF6627C");
    pub const KIND_CONFIG: Id = id_hex!("0D7F4BBE36BD0D6FF4E6C651110D6E8B");
}

/// One native commit projected from one verified legacy authored commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamsMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
}

/// Conservation summary for one complete migration plan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TeamsMigrationReport {
    pub authored_commits: usize,
    pub authored_empty_commits: usize,
    pub retired_only_commits: usize,
    pub contentless_merges: usize,
    pub source_facts: usize,
    pub facts: usize,
    pub retired_facts: usize,
}

/// Pure stopped-world plan ready for native collection publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamsMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<TeamsMigrationCommit>,
    source: TribleSet,
    retired: TribleSet,
    report: TeamsMigrationReport,
}

impl TeamsMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[TeamsMigrationCommit] {
        &self.commits
    }

    pub fn original_facts(&self) -> &TribleSet {
        &self.source
    }

    pub fn retired_facts(&self) -> &TribleSet {
        &self.retired
    }

    pub const fn report(&self) -> &TeamsMigrationReport {
        &self.report
    }

    pub fn materialized_facts(&self) -> TribleSet {
        self.commits
            .iter()
            .flat_map(|commit| commit.fragment.facts().iter().copied())
            .collect()
    }

    pub fn verify_conservation(&self) -> Result<()> {
        let materialized = self.materialized_facts();
        if !materialized.intersect(&self.retired).is_empty() {
            bail!("planned native Teams facts overlap retired OAuth evidence");
        }
        let mut reconstructed = materialized.clone();
        reconstructed += self.retired.clone();
        if reconstructed != self.source {
            bail!(
                "planned Teams facts union retired OAuth evidence do not exactly reconstruct the legacy source"
            );
        }
        if self.report.authored_commits != self.commits.len()
            || self.report.source_facts != self.source.len()
            || self.report.facts != materialized.len()
            || self.report.retired_facts != self.retired.len()
            || self.report.authored_empty_commits + self.report.retired_only_commits
                != self
                    .commits
                    .iter()
                    .filter(|commit| commit.fragment.facts().is_empty())
                    .count()
        {
            bail!("Teams migration report disagrees with its planned commits");
        }
        Ok(())
    }
}

fn retired_oauth_facts(source_facts: &TribleSet) -> Result<TribleSet> {
    let credential_attributes = [
        legacy::access_token.id(),
        legacy::refresh_token.id(),
        legacy::client_secret.id(),
    ];
    let credential_subjects = source_facts
        .iter()
        .filter(|fact| credential_attributes.contains(fact.a()))
        .map(|fact| *fact.e())
        .collect::<BTreeSet<_>>();
    let mut subjects = find!(
        subject: Id,
        pattern!(source_facts, [{ ?subject @ metadata::tag: legacy::KIND_TOKEN }])
    )
    .collect::<BTreeSet<_>>();
    subjects.extend(find!(
        subject: Id,
        pattern!(source_facts, [{ ?subject @ metadata::tag: legacy::KIND_CONFIG }])
    ));
    if !credential_subjects.is_subset(&subjects) {
        bail!(
            "legacy Teams credential attributes occur outside a typed token/config row: {:?}",
            credential_subjects
                .difference(&subjects)
                .collect::<Vec<_>>()
        );
    }

    let token_attributes = [
        metadata::tag.id(),
        metadata::created_at.id(),
        metadata::expires_at.id(),
        legacy::local_kind.id(),
        legacy::created_at_le.id(),
        legacy::created_at_ordered.id(),
        legacy::expires_at.id(),
        legacy::access_token.id(),
        legacy::refresh_token.id(),
        legacy::token_type.id(),
        legacy::scope.id(),
        legacy::tenant.id(),
        legacy::client_id.id(),
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    let config_attributes = [
        metadata::tag.id(),
        metadata::name.id(),
        metadata::description.id(),
        metadata::created_at.id(),
        legacy::local_kind.id(),
        legacy::created_at_le.id(),
        legacy::created_at_ordered.id(),
        legacy::tenant.id(),
        legacy::client_id.id(),
        legacy::client_secret.id(),
        teams::user_id.id(),
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    for subject in &subjects {
        let tags = find!(
            tag: Id,
            pattern!(source_facts, [{ *subject @ metadata::tag: ?tag }])
        )
        .collect::<BTreeSet<_>>();
        let (allowed, required) = if tags == BTreeSet::from([legacy::KIND_TOKEN]) {
            (
                &token_attributes,
                vec![
                    metadata::tag.id(),
                    metadata::created_at.id(),
                    legacy::access_token.id(),
                    legacy::tenant.id(),
                    legacy::client_id.id(),
                ],
            )
        } else if tags == BTreeSet::from([legacy::KIND_CONFIG]) {
            (
                &config_attributes,
                vec![metadata::tag.id(), metadata::created_at.id()],
            )
        } else {
            bail!("legacy Teams OAuth row {subject:x} has unexpected tags {tags:?}");
        };
        let local_tags = find!(
            tag: Id,
            pattern!(source_facts, [{ *subject @ legacy::local_kind: ?tag }])
        )
        .collect::<BTreeSet<_>>();
        if !local_tags.is_empty() && local_tags != tags {
            bail!(
                "legacy Teams OAuth row {subject:x} has a protocol-local kind inconsistent with metadata::tag"
            );
        }
        let row = source_facts
            .iter()
            .filter(|fact| fact.e() == subject)
            .collect::<Vec<_>>();
        if let Some(fact) = row.iter().find(|fact| !allowed.contains(fact.a())) {
            bail!(
                "legacy Teams OAuth row {subject:x} contains unexpected attribute {:x}",
                fact.a()
            );
        }
        for attribute in allowed {
            let count = row.iter().filter(|fact| fact.a() == attribute).count();
            if count > 1 {
                bail!(
                    "legacy Teams OAuth row {subject:x} has {count} values for attribute {attribute:x}"
                );
            }
        }
        for attribute in required {
            if !row.iter().any(|fact| fact.a() == &attribute) {
                bail!("legacy Teams OAuth row {subject:x} lacks required attribute {attribute:x}");
            }
        }
        if tags == BTreeSet::from([legacy::KIND_TOKEN])
            && !row.iter().any(|fact| {
                fact.a() == &metadata::expires_at.id() || fact.a() == &legacy::expires_at.id()
            })
        {
            bail!("legacy Teams OAuth row {subject:x} lacks an expiry attribute");
        }
    }

    Ok(source_facts
        .iter()
        .filter(|fact| subjects.contains(fact.e()))
        .copied()
        .collect())
}

fn direct_blob_roots(reader: &PileReader, facts: &TribleSet) -> BTreeSet<[u8; 32]> {
    facts
        .iter()
        .filter_map(|fact| {
            let raw = fact.v::<triblespace::prelude::inlineencodings::R256>().raw;
            let handle = Inline::<Handle<UnknownBlob>>::new(raw);
            reader
                .get::<Blob<UnknownBlob>, UnknownBlob>(handle)
                .ok()
                .map(|_| raw)
        })
        .collect()
}

/// Rehydrate the blob closure reachable from retained facts.
///
/// Handles identify content, not authority. The same public string can be
/// referenced by both a retained observation and a retired OAuth row, so a
/// root shared with `retired_roots` must still be staged when retained facts
/// require it. Descending through arbitrary blob bytes remains conservative:
/// an exact retired root is not followed unless retained facts directly name
/// it.
fn stage_retained_payloads(
    reader: &PileReader,
    facts: &TribleSet,
    retired_roots: &BTreeSet<[u8; 32]>,
    destination: &mut Fragment,
) -> Result<()> {
    let roots = direct_blob_roots(reader, facts);
    let excluded = retired_roots;
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    for raw in &roots {
        let handle = Inline::<Handle<UnknownBlob>>::new(*raw);
        let blob: Blob<UnknownBlob> = reader.get(handle).with_context(|| {
            format!("read retained Teams attachment {}", hex::encode_upper(raw))
        })?;
        if seen.insert(*raw) {
            queue.push_back(blob);
        }
    }
    while let Some(blob) = queue.pop_front() {
        for raw in blob.bytes.as_ref().chunks_exact(32) {
            let mut candidate = [0; 32];
            candidate.copy_from_slice(raw);
            if (excluded.contains(&candidate) && !roots.contains(&candidate))
                || seen.contains(&candidate)
            {
                continue;
            }
            let handle = Inline::<Handle<UnknownBlob>>::new(candidate);
            if let Ok(child) = reader.get::<Blob<UnknownBlob>, UnknownBlob>(handle) {
                seen.insert(candidate);
                queue.push_back(child);
            }
        }
        destination.blobs_mut().insert(blob);
    }
    Ok(())
}

fn rebuild_metadata_payloads(
    metadata: Fragment,
    retired_roots: &BTreeSet<[u8; 32]>,
) -> Result<Fragment> {
    let (_, facts, metafacts, mut blobs) = metadata.into_parts();
    // Commit metadata is already projected from the verified legacy commit
    // record. Its facts are the semantic authority boundary; a matching
    // content handle does not make one metadata fact an OAuth fact because
    // content-addressed public strings legitimately dedup. Preserve directly
    // referenced roots and exclude only unreferenced retired payloads from the
    // resident blob set.
    let direct = facts
        .iter()
        .chain(metafacts.iter())
        .map(|fact| fact.v::<triblespace::prelude::inlineencodings::R256>().raw)
        .collect::<BTreeSet<_>>();
    let excluded = retired_roots;
    if !excluded.is_empty() {
        let reader = blobs
            .reader()
            .context("snapshot projected Teams commit-metadata closure")?;
        blobs = reader
            .into_iter()
            .filter(|(handle, _)| !excluded.contains(&handle.raw) || direct.contains(&handle.raw))
            .collect();
    }
    Ok(Fragment::from_parts(facts, metafacts, blobs))
}

/// Plan the complete named legacy Teams branch without mutating its pile.
pub fn plan(source: &FrozenSource) -> Result<TeamsMigrationPlan> {
    let branch = source
        .legacy_branch(LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Teams branch"))?;
    let contentless_merges = branch
        .deltas
        .iter()
        .filter(|delta| !delta.is_authored())
        .count();
    // The projector has already verified the complete ancestry and returns
    // authored commits in parent-before-child order. Keep that order for
    // crash-recoverable publication; never replace it with a hash sort.
    let projected = project_legacy_authored_commits(source, &branch, validate_known_payloads)
        .context("project frozen Teams authored commits")?;
    let mut seen = BTreeSet::new();
    for commit in &projected {
        if !seen.insert(commit.source) {
            bail!(
                "Teams migration input repeats legacy authored commit {}",
                hex::encode_upper(commit.source.commit.raw)
            );
        }
    }

    let source_pin = branch.pin_coordinate();
    let source_facts = projected
        .iter()
        .fold(TribleSet::new(), |mut all, projected| {
            all += projected.content.facts().clone();
            all
        });
    let retired = retired_oauth_facts(&source_facts)
        .context("validate bounded retired legacy Teams OAuth rows")?;
    let retained = source_facts.difference(&retired);
    let retired_roots = direct_blob_roots(source.reader(), &retired);
    capability::validate_catalog(source.reader(), &retained)
        .context("validate retained legacy Teams catalog and payloads")?;

    let mut authored_empty_commits = 0;
    let mut retired_only_commits = 0;
    let mut commits = Vec::with_capacity(projected.len());
    for projected in projected {
        if projected.source.branch != source_pin.id || projected.source.pin != source_pin.value {
            bail!("Teams authored commits do not belong to one frozen branch pin");
        }
        if projected.content.facts().is_empty() {
            authored_empty_commits += 1;
        }
        let retained_facts = projected.content.facts().difference(&retired);
        if !projected.content.facts().is_empty() && retained_facts.is_empty() {
            retired_only_commits += 1;
        }
        let mut fragment = Fragment::from(retained_facts);
        let staged_facts = fragment.facts().clone();
        stage_retained_payloads(
            source.reader(),
            &staged_facts,
            &retired_roots,
            &mut fragment,
        )
        .with_context(|| {
            format!(
                "stage retained Teams payloads from {}",
                hex::encode_upper(projected.source.commit.raw)
            )
        })?;
        let metadata = rebuild_metadata_payloads(projected.metadata, &retired_roots)?;
        fragment.describe_with(metadata);
        commits.push(TeamsMigrationCommit {
            source: projected.source,
            fragment,
        });
    }

    let plan = TeamsMigrationPlan {
        source_pin,
        report: TeamsMigrationReport {
            authored_commits: commits.len(),
            authored_empty_commits,
            retired_only_commits,
            contentless_merges,
            source_facts: source_facts.len(),
            facts: retained.len(),
            retired_facts: retired.len(),
        },
        commits,
        source: source_facts,
        retired,
    };
    plan.verify_conservation()?;
    Ok(plan)
}

/// Publish a verified plan through the fixed native Teams collection.
///
/// Every legacy writer must remain stopped from freezing through publication.
/// Exact replay is content-addressed and idempotent.
pub fn publish(
    source: &FrozenSource,
    plan: &TeamsMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Teams migration plan does not belong to this frozen source");
    }
    plan.verify_conservation()?;

    // Load authority before touching the target. Keep one pile open for the
    // exact-union preflight and all commits. Existing facts need not be a
    // valid catalog alone, because a killed prior run may have published only
    // a proper prefix; the complete post-migration union must be valid.
    let signer = load_signer(target, key)?;
    let pile = open_pile_strict(target)?;
    let mut collection = Collection::new(pile, DEFAULT_SCOPE_ID, signer);
    let result = (|| {
        let existing = collection
            .materialize()
            .context("materialize existing native Teams value")?;
        let reader = collection
            .storage_mut()
            .reader()
            .context("open Teams publication attachment reader")?;
        let staged = plan
            .commits
            .iter()
            .fold(Fragment::empty(), |mut all, commit| {
                all += commit.fragment.clone();
                all
            });
        capability::validate_candidate(&reader, &existing, &staged)
            .context("preflight existing native value union legacy Teams plan")?;

        let mut published = Vec::with_capacity(plan.commits.len());
        for commit in &plan.commits {
            published.push(
                collection
                    .commit(commit.fragment.clone())
                    .with_context(|| {
                        format!(
                            "publish Teams commit projected from {}",
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
        (Ok(_), Err(error)) => Err(anyhow!("close Teams target pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Teams target pile also failed: {close_error}"
        ))),
    }
}

/// Strictly load every directly typed payload in one legacy delta.
fn validate_known_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    let text_attributes = [
        teams::chat_id.id(),
        teams::message_id.id(),
        teams::message_raw.id(),
        teams::user_id.id(),
        legacy::delta_link.id(),
        legacy::access_token.id(),
        legacy::refresh_token.id(),
        legacy::token_type.id(),
        legacy::scope.id(),
        legacy::tenant.id(),
        legacy::client_id.id(),
        legacy::client_secret.id(),
        archive::content.id(),
        archive::author_name.id(),
        archive::attachment_source_id.id(),
        archive::attachment_source_pointer.id(),
        archive::attachment_name.id(),
        file::name.id(),
        metadata::name.id(),
        metadata::description.id(),
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    for fact in facts {
        if text_attributes.contains(fact.a()) {
            let handle = *fact.v::<Handle<LongString>>();
            let _: anybytes::View<str> = reader.get(handle).with_context(|| {
                format!(
                    "read frozen Teams text payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        } else if fact.a() == &legacy::attachment_data.id() || fact.a() == &file::content.id() {
            let handle = *fact.v::<Handle<RawBytes>>();
            let _: Bytes = reader.get(handle).with_context(|| {
                format!(
                    "read frozen Teams byte payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        } else if fact.a() == &metadata::value_formatter.id() {
            let handle = *fact.v::<Handle<WasmCode>>();
            let _: Blob<WasmCode> = reader.get(handle).with_context(|| {
                format!(
                    "read frozen Teams value formatter {}",
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
    use triblespace::core::collection::simplearchive_union;
    use triblespace::core::repo::{PinStore, Repository};

    use super::*;
    use crate::collection_cutover::{
        discover_target, freeze_source, initialize_signer, load_signer, open_pile_strict,
    };

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-teams-cutover-{}-{serial}",
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
    }

    #[derive(Clone, Copy)]
    enum LegacyExpiryVocabulary {
        Canonical,
        Teams,
        Both,
    }

    fn fixture() -> Fixture {
        fixture_with_oauth_options(false, LegacyExpiryVocabulary::Canonical)
    }

    fn fixture_with_oauth_metadata_alias(alias_oauth_payload: bool) -> Fixture {
        fixture_with_oauth_options(alias_oauth_payload, LegacyExpiryVocabulary::Canonical)
    }

    fn fixture_with_oauth_options(
        alias_oauth_payload: bool,
        expiry_vocabulary: LegacyExpiryVocabulary,
    ) -> Fixture {
        fixture_with_options(alias_oauth_payload, expiry_vocabulary, false)
    }

    fn fixture_with_options(
        alias_oauth_payload: bool,
        expiry_vocabulary: LegacyExpiryVocabulary,
        shared_public_user: bool,
    ) -> Fixture {
        let directory = TestDirectory::new();
        let pile_path = directory.0.join("teams.pile");
        let key = directory.0.join("teams.key");
        File::create(&pile_path).unwrap();

        let pile = open_pile_strict(&pile_path).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0x71; 32]), Fragment::empty()).unwrap();
        let branch = *repository.create_branch(LEGACY_BRANCH_NAME, None).unwrap();
        let mut workspace = repository.pull(branch).unwrap();

        let chat = Id::new([0x11; 16]).unwrap();
        let mut chat_fragment = Fragment::empty();
        let chat_external = chat_fragment.put::<LongString, _>("legacy-chat".to_owned());
        chat_fragment += entity! { ExclusiveId::force_ref(&chat) @
            metadata::tag: teams::kind_chat,
            teams::chat_id: chat_external,
        };
        if shared_public_user {
            let author = Id::new([0x12; 16]).unwrap();
            let user = chat_fragment.put::<LongString, _>("historical-user".to_owned());
            chat_fragment += entity! { ExclusiveId::force_ref(&author) @
                metadata::tag: archive::kind_author,
                teams::user_id: user,
            };
        }
        workspace.commit_with_metadata(
            chat_fragment.clone(),
            entity! { metadata::description: "legacy chat provenance" },
            "legacy chat",
        );
        repository.push(&mut workspace).unwrap();

        let token = Id::new([0x22; 16]).unwrap();
        let config = Id::new([0x23; 16]).unwrap();
        let mut token_fragment = Fragment::empty();
        let secret = token_fragment.put::<LongString, _>("historical-secret".to_owned());
        let refresh = token_fragment.put::<LongString, _>("historical-refresh".to_owned());
        let tenant = token_fragment.put::<LongString, _>("historical-tenant".to_owned());
        let client = token_fragment.put::<LongString, _>("historical-client".to_owned());
        let client_secret =
            token_fragment.put::<LongString, _>("historical-client-secret".to_owned());
        let user = token_fragment.put::<LongString, _>("historical-user".to_owned());
        let at = hifitime::Epoch::from_tai_seconds(1.0);
        let at = (at, at).try_to_inline().unwrap();
        token_fragment += entity! { ExclusiveId::force_ref(&token) @
            metadata::tag: legacy::KIND_TOKEN,
            metadata::created_at: at,
            legacy::access_token: secret,
            legacy::refresh_token: refresh,
            legacy::tenant: tenant,
            legacy::client_id: client,
        };
        if matches!(
            expiry_vocabulary,
            LegacyExpiryVocabulary::Canonical | LegacyExpiryVocabulary::Both
        ) {
            token_fragment += entity! { ExclusiveId::force_ref(&token) @
                metadata::expires_at: at,
            };
        }
        if matches!(
            expiry_vocabulary,
            LegacyExpiryVocabulary::Teams | LegacyExpiryVocabulary::Both
        ) {
            token_fragment += entity! { ExclusiveId::force_ref(&token) @
                legacy::expires_at: at,
            };
        }
        if matches!(expiry_vocabulary, LegacyExpiryVocabulary::Both) {
            token_fragment += entity! { ExclusiveId::force_ref(&token) @
                legacy::local_kind: legacy::KIND_TOKEN,
                legacy::created_at_le: at,
                legacy::created_at_ordered: at,
            };
        }
        token_fragment += entity! { ExclusiveId::force_ref(&config) @
            metadata::tag: legacy::KIND_CONFIG,
            metadata::created_at: at,
            legacy::tenant: tenant,
            legacy::client_id: client,
            legacy::client_secret: client_secret,
            teams::user_id: user,
        };
        if matches!(expiry_vocabulary, LegacyExpiryVocabulary::Both) {
            token_fragment += entity! { ExclusiveId::force_ref(&config) @
                legacy::local_kind: legacy::KIND_CONFIG,
                legacy::created_at_le: at,
                legacy::created_at_ordered: at,
            };
        }
        if matches!(expiry_vocabulary, LegacyExpiryVocabulary::Both) {
            let name = token_fragment.put::<LongString, _>("kind_config".to_owned());
            let description =
                token_fragment.put::<LongString, _>("Teams app configuration kind.".to_owned());
            token_fragment += entity! { ExclusiveId::force_ref(&config) @
                metadata::name: name,
                metadata::description: description,
            };
        }
        if alias_oauth_payload {
            workspace.commit_with_metadata(
                token_fragment.clone(),
                entity! { metadata::description: secret },
                "legacy token evidence",
            );
        } else {
            workspace.commit(token_fragment.clone(), "legacy token evidence");
        }
        repository.push(&mut workspace).unwrap();

        // Empty authored commits retain provenance, unlike contentless merge
        // nodes which are only verified ancestry.
        workspace.commit(Fragment::empty(), "legacy authored empty");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();

        let mut source_facts = chat_fragment.into_facts();
        source_facts += token_fragment.into_facts();
        initialize_signer(&pile_path, Some(&key)).unwrap();
        Fixture {
            _directory: directory,
            pile: pile_path,
            key,
            source_facts,
        }
    }

    #[test]
    fn plan_retires_complete_oauth_rows_and_keeps_authored_empty_commits() {
        let fixture = fixture();
        let frozen = freeze_source(&fixture.pile).unwrap();
        let plan = plan(&frozen).unwrap();

        plan.verify_conservation().unwrap();
        assert_eq!(plan.original_facts(), &fixture.source_facts);
        assert_eq!(plan.report().authored_commits, 3);
        assert_eq!(plan.report().authored_empty_commits, 1);
        assert_eq!(plan.report().retired_only_commits, 1);
        assert_eq!(plan.report().retired_facts, 13);
        assert!(plan.commits().iter().any(|commit| {
            commit.fragment.facts().is_empty() && !commit.fragment.metafacts().is_empty()
        }));
        assert!(!plan.materialized_facts().iter().any(|fact| [
            legacy::access_token.id(),
            legacy::refresh_token.id(),
            legacy::client_secret.id(),
        ]
        .contains(fact.a())));
        assert!(plan
            .retired_facts()
            .iter()
            .any(|fact| fact.a() == &legacy::access_token.id()));
        for commit in plan.commits() {
            for plaintext in [
                b"historical-secret".as_slice(),
                b"historical-refresh".as_slice(),
                b"historical-client-secret".as_slice(),
            ] {
                let mut blobs = commit.fragment.blobs().clone();
                assert!(blobs.reader().unwrap().into_iter().all(|(_, blob)| !blob
                    .bytes
                    .as_ref()
                    .windows(plaintext.len())
                    .any(|window| window == plaintext)));
            }
        }
    }

    #[test]
    fn plan_retires_token_rows_with_the_original_teams_expiry_attribute() {
        let fixture = fixture_with_oauth_options(false, LegacyExpiryVocabulary::Teams);
        let frozen = freeze_source(&fixture.pile).unwrap();
        let plan = plan(&frozen).unwrap();

        plan.verify_conservation().unwrap();
        assert_eq!(plan.original_facts(), &fixture.source_facts);
        assert!(plan
            .retired_facts()
            .iter()
            .any(|fact| fact.a() == &legacy::expires_at.id()));
        assert!(!plan
            .materialized_facts()
            .iter()
            .any(|fact| fact.a() == &legacy::expires_at.id()));
    }

    #[test]
    fn plan_retires_token_rows_spanning_both_expiry_vocabularies() {
        let fixture = fixture_with_oauth_options(false, LegacyExpiryVocabulary::Both);
        let frozen = freeze_source(&fixture.pile).unwrap();
        let plan = plan(&frozen).unwrap();

        plan.verify_conservation().unwrap();
        assert_eq!(plan.original_facts(), &fixture.source_facts);
        for attribute in [
            metadata::expires_at.id(),
            legacy::expires_at.id(),
            legacy::local_kind.id(),
            legacy::created_at_le.id(),
            legacy::created_at_ordered.id(),
            metadata::name.id(),
            metadata::description.id(),
        ] {
            assert!(plan
                .retired_facts()
                .iter()
                .any(|fact| fact.a() == &attribute));
        }
    }

    #[test]
    fn plan_preserves_metadata_that_content_deduplicates_with_retired_oauth() {
        let fixture = fixture_with_oauth_metadata_alias(true);
        let frozen = freeze_source(&fixture.pile).unwrap();
        let plan = plan(&frozen).unwrap();

        assert!(plan
            .commits()
            .iter()
            .any(|commit| !commit.fragment.metafacts().is_empty()));
        plan.verify_conservation().unwrap();
    }

    #[test]
    fn retained_public_payload_may_deduplicate_with_retired_config() {
        let fixture = fixture_with_options(false, LegacyExpiryVocabulary::Canonical, true);
        let frozen = freeze_source(&fixture.pile).unwrap();
        let plan = plan(&frozen).unwrap();
        let retained = plan.materialized_facts();
        let user_handle = find!(
            value: Inline<Handle<LongString>>,
            pattern!(&retained, [{ _?author @ teams::user_id: ?value }])
        )
        .next()
        .expect("retained author user id");

        assert!(plan.retired_facts().iter().any(|fact| {
            fact.a() == &teams::user_id.id() && fact.v::<Handle<LongString>>() == &user_handle
        }));
        assert!(plan.commits().iter().any(|commit| {
            let mut blobs = commit.fragment.blobs().clone();
            blobs
                .reader()
                .unwrap()
                .get::<anybytes::View<str>, LongString>(user_handle)
                .is_ok()
        }));
        for commit in plan.commits() {
            for plaintext in [
                b"historical-secret".as_slice(),
                b"historical-refresh".as_slice(),
                b"historical-client-secret".as_slice(),
            ] {
                let mut blobs = commit.fragment.blobs().clone();
                assert!(blobs.reader().unwrap().into_iter().all(|(_, blob)| !blob
                    .bytes
                    .as_ref()
                    .windows(plaintext.len())
                    .any(|window| window == plaintext)));
            }
        }
    }

    #[test]
    fn publication_is_idempotent_uses_descriptor_handle_and_retains_legacy_pin() {
        let fixture = fixture();
        let frozen = freeze_source(&fixture.pile).unwrap();
        let plan = plan(&frozen).unwrap();

        let first = publish(&frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        let after_first = fs::metadata(&fixture.pile).unwrap().len();
        let second = publish(&frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(first, second);
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), after_first);

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection = Collection::new(pile, DEFAULT_SCOPE_ID, signer);
        let facts = collection.materialize().unwrap();
        assert_eq!(facts, fixture.source_facts.difference(plan.retired_facts()));
        let reader = collection.storage_mut().reader().unwrap();
        capability::validate_catalog(&reader, &facts).unwrap();
        let discovery = discover_target(collection.storage_mut(), DEFAULT_SCOPE_ID).unwrap();
        assert_eq!(
            discovery.descriptor(),
            simplearchive_union::descriptor(DEFAULT_SCOPE_ID)
        );
        assert_eq!(discovery.commits().len(), plan.commits().len());
        let mut pile = collection.into_storage();
        assert_eq!(
            pile.head(plan.source_pin().id).unwrap(),
            Some(plan.source_pin().value)
        );
        pile.close().unwrap();
    }

    #[test]
    fn publication_resumes_from_an_incomplete_existing_subset() {
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

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection = Collection::new(pile, DEFAULT_SCOPE_ID, signer);
        assert_eq!(
            collection.materialize().unwrap(),
            fixture.source_facts.difference(plan.retired_facts())
        );
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn publication_rejects_plaintext_oauth_from_the_previous_native_migration() {
        let fixture = fixture();
        let frozen = freeze_source(&fixture.pile).unwrap();
        let plan = plan(&frozen).unwrap();

        // The immediately preceding migration implementation published the
        // complete legacy value into this same native collection. Recreate its
        // semantic result so an additive retry cannot pretend to sanitize it.
        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection = Collection::new(pile, DEFAULT_SCOPE_ID, signer);
        collection
            .commit(Fragment::from(fixture.source_facts.clone()))
            .unwrap();
        collection.into_storage().close().unwrap();
        let before = fs::metadata(&fixture.pile).unwrap().len();

        let error = publish(&frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap_err();
        assert!(
            format!("{error:#}").contains("retired plaintext OAuth evidence"),
            "unexpected error: {error:#}"
        );
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), before);
    }

    #[test]
    fn invalid_native_union_fails_before_any_migration_append() {
        let fixture = fixture();
        let frozen = freeze_source(&fixture.pile).unwrap();
        let plan = plan(&frozen).unwrap();

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection = Collection::new(pile, DEFAULT_SCOPE_ID, signer);
        let source = capability::source_fragment("tenant-a");
        let source_id = source.root().unwrap();
        let mut context = capability::context_fragment(
            source_id,
            Inline::new([0x33; 32]),
            [],
            "Bulti",
            "professional",
        )
        .unwrap();
        let context_id = context.root().unwrap();
        context += source;
        let other_name = context.put::<LongString, _>("Other".to_owned());
        context += entity! { ExclusiveId::force_ref(&context_id) @ metadata::name: other_name };
        collection.commit(context).unwrap();
        collection.into_storage().close().unwrap();
        let before = fs::metadata(&fixture.pile).unwrap().len();

        let error = publish(&frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap_err();
        assert!(format!("{error:#}").contains("preflight existing native value"));
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), before);
    }

    #[test]
    fn missing_durable_signer_fails_without_growing_the_pile() {
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
