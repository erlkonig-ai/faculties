//! Bounded stopped-world migration of the legacy Secrets branch.
//!
//! Canonical Secrets facts retain their exact identities and authored commit
//! partition. The same historical branch also contains a retired four-fact
//! Mail-account record and three-fact active pointer vocabulary. Those records
//! are validated exactly and accounted for by the migration conservation law,
//! but deliberately do not enter the native Secrets collection or confer
//! authority. Semantic commit metadata remains commit metadata; contentless
//! merge nodes and retired-only authored commits remain empty authority.

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::attribute::Attribute;
use triblespace::core::blob::encodings::UnknownBlob;
use triblespace::core::blob::Blob;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::inline::{Inline, InlineEncoding};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet};
use triblespace::prelude::*;

use crate::collection_cutover::{
    project_legacy_authored_commits, FrozenSource, LegacyCommitCoordinate, LegacyPinCoordinate,
};
use faculties::secrets::{self as capability, schema};
use faculties::storage::{load_signer, open_pile_strict};

/// Exact historical Mail vocabulary which was written onto the branch named
/// `secrets`. It is intentionally local to cutover: current Secrets and Mail
/// catalogs neither expose nor authorize through these retired records.
mod retired_mail {
    use super::*;

    pub const KIND_ACCOUNT: Id = triblespace::macros::id_hex!("BC1F0E3D5DB2DC2AD00AE42FCF3AD495");
    pub const KIND_ACTIVE: Id = triblespace::macros::id_hex!("792EC015AB18E82DBB001A30B4CA2C0A");

    attributes! {
        "7F0AE7B9E5D59E9DF7EB539AD75CEE6D" unsafe as pub address:
            inlineencodings::ShortString;
        "7C878C936BCF83E1905C8FB58DEC29ED" unsafe as pub r#box:
            inlineencodings::Handle<blobencodings::RawBytes>;
    }
}

type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
type BytesHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;

/// One native commit projected from one verified legacy authored commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretsMigrationCommit {
    pub source: LegacyCommitCoordinate,
    pub fragment: Fragment,
}

/// Conservation summary for a complete Secrets migration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SecretsMigrationReport {
    /// Authored legacy deltas, including empty and retired-only deltas.
    pub authored_commits: usize,
    /// Deltas whose source fact set was already empty.
    pub authored_empty_commits: usize,
    /// Non-empty source deltas whose every fact belonged to bounded retired
    /// Mail evidence and therefore publish empty Secrets authority.
    pub retired_only_commits: usize,
    /// Exact fact count at the verified legacy branch head.
    pub source_facts: usize,
    /// Retained canonical Secrets facts published by this plan.
    pub facts: usize,
    /// Exact historical Mail facts validated and deliberately not published.
    pub retired_facts: usize,
}

/// Pure stopped-world plan ready for native collection publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretsMigrationPlan {
    source_pin: LegacyPinCoordinate,
    commits: Vec<SecretsMigrationCommit>,
    source: TribleSet,
    retired: TribleSet,
    report: SecretsMigrationReport,
}

impl SecretsMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn commits(&self) -> &[SecretsMigrationCommit] {
        &self.commits
    }

    pub fn source_facts(&self) -> &TribleSet {
        &self.source
    }

    /// Exact bounded evidence omitted from native Secrets authority.
    pub fn retired_facts(&self) -> &TribleSet {
        &self.retired
    }

    pub const fn report(&self) -> &SecretsMigrationReport {
        &self.report
    }

    pub fn materialized_facts(&self) -> TribleSet {
        self.commits
            .iter()
            .flat_map(|commit| commit.fragment.facts().iter().copied())
            .collect()
    }

    /// Recheck the exact conservation law independently of publication.
    pub fn verify_conservation(&self) -> Result<()> {
        let materialized = self.materialized_facts();
        if !materialized.intersect(&self.retired).is_empty() {
            bail!("planned native Secrets facts overlap retired Mail evidence");
        }
        let mut reconstructed = materialized.clone();
        reconstructed += self.retired.clone();
        if reconstructed != self.source {
            bail!(
                "planned native Secrets facts union retired Mail evidence does not exactly reconstruct the legacy source"
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
            bail!("Secrets migration report disagrees with its planned commits");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RetiredMailEvidence {
    facts: TribleSet,
    box_handle: Option<BytesHandle>,
}

fn inline_values<E: InlineEncoding>(
    facts: &TribleSet,
    entity: Id,
    attribute: &Attribute<E>,
) -> Vec<Inline<E>> {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity && fact.a() == &attribute.id())
        .map(|fact| *fact.v::<E>())
        .collect()
}

fn exactly_one<T>(entity: Id, field: &str, mut values: Vec<T>) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "retired Mail entity {entity:X} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(values.pop().expect("length checked"))
}

fn validate_point(entity: Id, field: &str, value: IntervalValue) -> Result<()> {
    let (lower, upper): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode retired Mail {field} on {entity:X}: {error:?}"))?;
    if lower != upper {
        bail!("retired Mail {field} on {entity:X} must be a point interval");
    }
    Ok(())
}

fn decode_address(entity: Id, value: Inline<inlineencodings::ShortString>) -> Result<String> {
    let address: String = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode retired Mail address on {entity:X}: {error:?}"))?;
    if address.is_empty() || address.trim() != address || address.as_bytes().contains(&0) {
        bail!("retired Mail address on {entity:X} is not a canonical non-empty short string");
    }
    Ok(address)
}

fn entity_facts(facts: &TribleSet, entity: Id) -> TribleSet {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity)
        .copied()
        .collect()
}

fn retired_account_record(
    id: Id,
    created_at: IntervalValue,
    address: &str,
    r#box: BytesHandle,
) -> Fragment {
    entity! { ExclusiveId::force_ref(&id) @
        metadata::tag: &retired_mail::KIND_ACCOUNT,
        metadata::created_at: created_at,
        retired_mail::address: address,
        retired_mail::r#box: r#box,
    }
}

fn retired_active_record(id: Id, created_at: IntervalValue, address: &str) -> Fragment {
    entity! { ExclusiveId::force_ref(&id) @
        metadata::tag: &retired_mail::KIND_ACTIVE,
        metadata::created_at: created_at,
        retired_mail::address: address,
    }
}

fn tagged_entities(facts: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: kind }])).collect()
}

/// Validate the complete, bounded historical Mail sublanguage and return its
/// exact facts for retirement. Attachments are read by content handle, so a
/// missing or corrupt envelope fails before the source can be partitioned.
fn validate_retired_mail_evidence(
    reader: &PileReader,
    facts: &TribleSet,
) -> Result<RetiredMailEvidence> {
    let account_ids = tagged_entities(facts, retired_mail::KIND_ACCOUNT);
    let active_ids = tagged_entities(facts, retired_mail::KIND_ACTIVE);
    match (account_ids.len(), active_ids.len()) {
        (0, 0) | (1, 1) => {}
        (accounts, active) => bail!(
            "retired Mail evidence must be absent or exactly one account and one active pointer; found {accounts} account and {active} active records"
        ),
    }
    let mut retired = TribleSet::new();
    let mut addresses = BTreeSet::new();
    let mut box_handle = None;

    for id in account_ids {
        let created_at = exactly_one(
            id,
            "metadata::created_at",
            inline_values(facts, id, &metadata::created_at),
        )?;
        validate_point(id, "creation time", created_at)?;
        let address = decode_address(
            id,
            exactly_one(
                id,
                "address",
                inline_values(facts, id, &retired_mail::address),
            )?,
        )?;
        let r#box = exactly_one(id, "box", inline_values(facts, id, &retired_mail::r#box))?;
        let envelope: anybytes::Bytes = reader.get(r#box).with_context(|| {
            format!(
                "read retired Mail account envelope {} on {id:X}",
                hex::encode_upper(r#box.raw)
            )
        })?;
        // salt(16) || nonce(24) || secretbox MAC(16) || optional plaintext
        if envelope.len() < 16 + 24 + 16 {
            bail!(
                "retired Mail account envelope on {id:X} is shorter than its cryptographic framing"
            );
        }

        let actual = entity_facts(facts, id);
        let expected = retired_account_record(id, created_at, &address, r#box);
        if actual != *expected.facts() {
            bail!("retired Mail account {id:X} is not one exact four-fact record");
        }
        addresses.insert(address);
        box_handle = Some(r#box);
        retired += actual;
    }

    for id in active_ids {
        let created_at = exactly_one(
            id,
            "metadata::created_at",
            inline_values(facts, id, &metadata::created_at),
        )?;
        validate_point(id, "creation time", created_at)?;
        let address = decode_address(
            id,
            exactly_one(
                id,
                "address",
                inline_values(facts, id, &retired_mail::address),
            )?,
        )?;
        let actual = entity_facts(facts, id);
        let expected = retired_active_record(id, created_at, &address);
        if actual != *expected.facts() {
            bail!("retired Mail active pointer {id:X} is not one exact three-fact record");
        }
        if !addresses.contains(&address) {
            bail!(
                "retired Mail active pointer {id:X} names address {address:?} without an account record"
            );
        }
        retired += actual;
    }

    Ok(RetiredMailEvidence {
        facts: retired,
        box_handle,
    })
}

/// Rebuild one canonical authored partition with only its schema-known direct
/// attachments. In particular, the retired Mail envelope is not copied into
/// any native Secrets commit.
fn stage_canonical_payloads(
    reader: &PileReader,
    facts: &TribleSet,
    retired_box: Option<BytesHandle>,
    destination: &mut Fragment,
) -> Result<()> {
    let mut roots = BTreeSet::new();
    for fact in facts {
        let attribute = fact.a();
        if attribute == &capability::schema::identity_sign_pk.id()
            || attribute == &capability::schema::identity_lockbox.id()
            || attribute == &capability::schema::secret_body.id()
            || attribute == &capability::schema::wrap_dek.id()
        {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::RawBytes>>();
            roots.insert(handle.raw);
        } else if attribute == &metadata::name.id() {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::UTF8String>>();
            roots.insert(handle.raw);
        } else if attribute == &metadata::description.id() {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::UTF8String>>();
            roots.insert(handle.raw);
        }
    }

    let excluded = retired_box
        .map(|handle| handle.raw)
        .filter(|handle| !roots.contains(handle));
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    for raw in roots {
        let handle = Inline::<inlineencodings::Handle<UnknownBlob>>::new(raw);
        let blob: Blob<UnknownBlob> = reader.get(handle).with_context(|| {
            format!(
                "read canonical Secrets attachment {}",
                hex::encode_upper(handle.raw)
            )
        })?;
        if seen.insert(raw) {
            queue.push_back(blob);
        }
    }

    // Preserve the projection contract's conservative resident closure, but
    // do not let a random 32-byte word pull the deliberately retired envelope
    // back into native Secrets. If that handle is itself a canonical direct
    // root, content addressing makes the payload genuinely shared and it is
    // retained once.
    while let Some(blob) = queue.pop_front() {
        for raw in blob.bytes.as_ref().chunks_exact(32) {
            let mut candidate = [0; 32];
            candidate.copy_from_slice(raw);
            if excluded == Some(candidate) || seen.contains(&candidate) {
                continue;
            }
            let handle = Inline::<inlineencodings::Handle<UnknownBlob>>::new(candidate);
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
    retired_box: Option<BytesHandle>,
) -> Result<Fragment> {
    let (_, facts, metafacts, mut blobs) = metadata.into_parts();

    // `project_legacy_metadata` has already hydrated the conservative closure
    // rooted at the attached semantic-metadata SimpleArchive and commit
    // message. Keep that generic closure: semantic metadata deliberately may
    // use attributes unknown to Secrets, so re-discovering roots from a
    // Secrets-specific attribute list would silently detach their payloads.
    // The one bounded exception is the retired Mail envelope. Remove it when
    // it arrived only through conservative scanning, but retain it if an
    // explicit metadata fact genuinely names that same content handle.
    if let Some(retired_box) = retired_box {
        let direct = facts
            .iter()
            .chain(metafacts.iter())
            .any(|fact| fact.v::<inlineencodings::R256>().raw == retired_box.raw);
        if !direct {
            let reader = blobs
                .reader()
                .context("snapshot projected Secrets commit-metadata closure")?;
            blobs = reader
                .into_iter()
                .filter(|(handle, _)| handle.raw != retired_box.raw)
                .collect();
        }
    }
    Ok(Fragment::from_parts(facts, metafacts, blobs))
}

/// Plan the complete named legacy Secrets branch without mutating its pile.
pub fn plan(source: &FrozenSource) -> Result<SecretsMigrationPlan> {
    let branch = source
        .legacy_branch(schema::LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Secrets branch"))?;
    // Projection preserves parent-before-child order. That order is relevant
    // during crash-recoverable multi-commit publication, so do not replace it
    // with a hash sort.
    let projected = project_legacy_authored_commits(source, &branch, validate_known_payloads)
        .context("project frozen Secrets authored commits")?;
    let mut seen = std::collections::BTreeSet::new();
    for commit in &projected {
        if !seen.insert(commit.source) {
            bail!(
                "Secrets migration input repeats legacy authored commit {}",
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
    let retired = validate_retired_mail_evidence(source.reader(), &source_facts)
        .context("validate bounded retired Mail evidence on legacy Secrets branch")?;
    let canonical = source_facts.difference(&retired.facts);

    // Cross-delta references belong to the complete retained union. Retired
    // Mail evidence never enters this validator and therefore cannot acquire
    // Secrets authorization merely by sharing the old branch name.
    capability::validate_catalog(source.reader(), &canonical)
        .context("validate complete retained legacy Secrets catalog")?;

    let mut authored_empty_commits = 0;
    let mut retired_only_commits = 0;
    let mut commits = Vec::with_capacity(projected.len());
    for projected in projected {
        if projected.source.branch != source_pin.id || projected.source.pin != source_pin.value {
            bail!("Secrets authored commits do not belong to one frozen branch pin");
        }
        if projected.content.facts().is_empty() {
            authored_empty_commits += 1;
        }
        let retained_facts = projected.content.facts().difference(&retired.facts);
        if !projected.content.facts().is_empty() && retained_facts.is_empty() {
            retired_only_commits += 1;
        }
        let mut fragment = Fragment::from(retained_facts);
        let staged_facts = fragment.facts().clone();
        stage_canonical_payloads(
            source.reader(),
            &staged_facts,
            retired.box_handle,
            &mut fragment,
        )
        .with_context(|| {
            format!(
                "stage canonical Secrets payloads from {}",
                hex::encode_upper(projected.source.commit.raw)
            )
        })?;
        let metadata = rebuild_metadata_payloads(projected.metadata, retired.box_handle)
            .with_context(|| {
                format!(
                    "stage Secrets commit metadata from {}",
                    hex::encode_upper(projected.source.commit.raw)
                )
            })?;
        fragment.describe_with(metadata);
        commits.push(SecretsMigrationCommit {
            source: projected.source,
            fragment,
        });
    }

    let plan = SecretsMigrationPlan {
        source_pin,
        report: SecretsMigrationReport {
            authored_commits: commits.len(),
            authored_empty_commits,
            retired_only_commits,
            source_facts: source_facts.len(),
            facts: canonical.len(),
            retired_facts: retired.facts.len(),
        },
        commits,
        source: source_facts,
        retired: retired.facts,
    };
    plan.verify_conservation()?;
    Ok(plan)
}

/// Publish a verified plan through the fixed native Secrets collection.
///
/// All legacy writers must remain stopped from freezing through publication.
/// Exact replay is content-addressed and idempotent.
pub fn publish(
    source: &FrozenSource,
    plan: &SecretsMigrationPlan,
    target: &Path,
    key: Option<&Path>,
) -> Result<Vec<CollectionCommit>> {
    if !source.legacy_pins().contains(&plan.source_pin) {
        bail!("Secrets migration plan does not belong to this frozen source");
    }
    plan.verify_conservation()?;

    crate::write_authority::publish(target, key)
        .context("initialize WRITE authority before Secrets migration publication")?;

    // Load authority before touching the target, then keep one pile open for
    // exact-union preflight and every idempotent commit. Complete preflight
    // catches conflicts with existing native facts before anything is
    // appended. Existing facts need not form a valid catalog alone: that lets
    // replay finish after a process died on an earlier valid plan prefix.
    let signer = load_signer(target, key)?;
    let pile = open_pile_strict(target)?;
    let mut collection = faculties::collection_names::open(pile, schema::DEFAULT_SCOPE_ID, signer);
    let result = (|| {
        let existing = collection
            .materialize()
            .context("materialize existing native Secrets value")?;
        let reader = collection
            .storage_mut()
            .reader()
            .context("open Secrets publication attachment reader")?;
        let staged = plan
            .commits
            .iter()
            .fold(Fragment::empty(), |mut all, commit| {
                all += commit.fragment.clone();
                all
            });
        capability::validate_candidate(&reader, &existing, &staged)
            .context("preflight existing native value union legacy Secrets plan")?;

        let mut published = Vec::with_capacity(plan.commits.len());
        for commit in &plan.commits {
            published.push(
                collection
                    .commit(commit.fragment.clone())
                    .with_context(|| {
                        format!(
                            "publish Secrets commit projected from {}",
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
        (Ok(_), Err(error)) => Err(anyhow!("close Secrets target pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Secrets target pile also failed: {close_error}"
        ))),
    }
}

/// Strictly load every directly typed canonical or retired attachment in one
/// legacy delta before conservative source projection.
fn validate_known_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts {
        let attribute = fact.a();
        if attribute == &capability::schema::identity_sign_pk.id()
            || attribute == &capability::schema::identity_lockbox.id()
            || attribute == &capability::schema::secret_body.id()
            || attribute == &capability::schema::wrap_dek.id()
            || attribute == &retired_mail::r#box.id()
        {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::RawBytes>>();
            let _: anybytes::Bytes = reader.get(handle).with_context(|| {
                format!(
                    "strictly read legacy Secrets byte payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        } else if attribute == &metadata::name.id() {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::UTF8String>>();
            let _: anybytes::View<str> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read legacy Secrets name payload {}",
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
    use triblespace::core::repo::{BlobStore, BlobStoreMeta};

    use super::*;
    use crate::collection_cutover::test_support::{TestBranchSpec, TestDeltaSpec, TestSourceSpec};
    use faculties::storage::{initialize_signer, load_signer, open_pile_strict};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-secrets-cutover-{}-{serial}",
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
        identity: Id,
        scope: Id,
        source_facts: TribleSet,
        canonical_facts: TribleSet,
        retired_facts: TribleSet,
        retired_account: Id,
        retired_active: Id,
        retired_box: BytesHandle,
        canonical_child: BytesHandle,
        metadata_root: BytesHandle,
        metadata_child: BytesHandle,
        source: FrozenSource,
    }

    fn at(byte: u8) -> capability::IntervalValue {
        Inline::new([byte; 32])
    }

    fn fixture() -> Fixture {
        let directory = TestDirectory::new();
        let pile_path = directory.0.join("secrets.pile");
        let key = directory.0.join("secrets.key");
        File::create(&pile_path).unwrap();
        initialize_signer(&pile_path, Some(&key)).unwrap();
        crate::write_authority::publish(&pile_path, Some(&key)).unwrap();

        let identity = Id::new([0x11; 16]).unwrap();
        let mut identity_fragment = Fragment::empty();
        let name = identity_fragment.put("alice".to_owned());
        let canonical_child =
            identity_fragment.put::<blobencodings::RawBytes, _>(b"conservative child".to_vec());
        let public_key =
            identity_fragment.put::<blobencodings::RawBytes, _>(canonical_child.raw.to_vec());
        let lockbox =
            identity_fragment.put::<blobencodings::RawBytes, _>(vec![0x33; 16 + 24 + 16 + 64]);
        identity_fragment += entity! { ExclusiveId::force_ref(&identity) @
            metadata::tag: &schema::KIND_IDENTITY,
            metadata::created_at: at(1),
            metadata::name: name,
            schema::identity_sign_pk: public_key,
            schema::identity_lockbox: lockbox,
        };

        // The old Mail writer placed account state on this branch. It remains
        // an authored source delta, but becomes an empty native Secrets commit
        // after its complete bounded record is retired.
        let canonical_identity_facts = identity_fragment.facts().clone();
        let retired_account = Id::new([0x61; 16]).unwrap();
        let retired_active = Id::new([0x62; 16]).unwrap();
        let mut retired_fragment = Fragment::empty();
        let retired_box = retired_fragment.put::<blobencodings::RawBytes, _>(vec![0xA5; 64]);
        retired_fragment +=
            retired_account_record(retired_account, at(1), "archive@example.test", retired_box);
        retired_fragment += retired_active_record(retired_active, at(1), "archive@example.test");
        let retired_facts = retired_fragment.facts().clone();
        let mut semantic_metadata = entity! { metadata::description: "legacy identity provenance" };
        let metadata_child =
            semantic_metadata.put::<blobencodings::RawBytes, _>(b"unknown metadata child".to_vec());
        let metadata_root =
            semantic_metadata.put::<blobencodings::RawBytes, _>(metadata_child.raw.to_vec());
        semantic_metadata += entity! {
            faculties::schemas::files::file::content: metadata_root,
        };
        let identity_delta = TestDeltaSpec::authored(identity_fragment.clone(), "legacy identity")
            .with_metadata(semantic_metadata);

        // Construct a genuine first-epoch intrinsic scope. The migration must
        // conserve this id rather than silently re-rooting it under today's
        // complete-row entity! hash domain.
        let mut scope_fragment = Fragment::empty();
        let scope_name = scope_fragment.put("prod".to_owned());
        let creator: Inline<inlineencodings::GenId> = identity.to_inline();
        let scope = triblespace::core::trible::intrinsic_entity_id_v1(vec![
            (schema::scope_creator.id(), creator.raw),
            (metadata::name.id(), scope_name.raw),
        ]);
        scope_fragment += entity! { ExclusiveId::force_ref(&scope) @
            schema::scope_creator: identity,
            metadata::name: scope_name,
            metadata::tag: &schema::KIND_SCOPE,
            metadata::created_at: at(2),
        };
        let scope_facts = scope_fragment.facts().clone();
        let mut canonical_facts = canonical_identity_facts;
        canonical_facts += scope_facts.clone();
        let mut source_facts = canonical_facts.clone();
        source_facts += retired_facts.clone();
        let source = TestSourceSpec::new(vec![TestBranchSpec::new(
            schema::LEGACY_BRANCH_NAME,
            Id::new([0x51; 16]).unwrap(),
            SigningKey::from_bytes(&[0x51; 32]),
            vec![
                identity_delta,
                TestDeltaSpec::authored(scope_fragment, "legacy scope"),
                TestDeltaSpec::authored(retired_fragment, "retired Mail account evidence"),
                // Authored empty commits are semantic provenance and remain
                // native COMMIT records even though they add no ordinary facts.
                TestDeltaSpec::authored(Fragment::empty(), "legacy authored empty"),
            ],
        )])
        .freeze(&pile_path)
        .unwrap()
        .source;
        Fixture {
            _directory: directory,
            pile: pile_path,
            key,
            identity,
            scope,
            source_facts,
            canonical_facts,
            retired_facts,
            retired_account,
            retired_active,
            retired_box,
            canonical_child,
            metadata_root,
            metadata_child,
            source,
        }
    }

    #[test]
    fn plan_retires_exact_mail_evidence_and_keeps_authored_empty_commits() {
        let fixture = fixture();
        let frozen = &fixture.source;
        let plan = plan(frozen).unwrap();

        plan.verify_conservation().unwrap();
        assert_eq!(plan.source_facts(), &fixture.source_facts);
        assert_eq!(plan.retired_facts(), &fixture.retired_facts);
        assert_eq!(plan.materialized_facts(), fixture.canonical_facts);
        assert_eq!(plan.report().authored_commits, 4);
        assert_eq!(plan.report().authored_empty_commits, 1);
        assert_eq!(plan.report().retired_only_commits, 1);
        assert_eq!(plan.report().source_facts, fixture.source_facts.len());
        assert_eq!(plan.report().retired_facts, fixture.retired_facts.len());
        assert!(plan.commits().iter().any(|commit| {
            commit.fragment.facts().is_empty() && !commit.fragment.metafacts().is_empty()
        }));
        assert!(plan
            .materialized_facts()
            .iter()
            .any(|fact| fact.e() == &fixture.identity));
        assert!(plan
            .materialized_facts()
            .iter()
            .any(|fact| fact.e() == &fixture.scope));
        assert!(plan
            .materialized_facts()
            .iter()
            .all(|fact| fact.e() != &fixture.retired_account));
        assert!(plan.commits().iter().all(|commit| {
            let mut blobs = commit.fragment.blobs().clone();
            let reader = blobs.reader().unwrap();
            reader.metadata(fixture.retired_box).unwrap().is_none()
        }));
        assert!(plan.commits().iter().any(|commit| {
            let mut blobs = commit.fragment.blobs().clone();
            let reader = blobs.reader().unwrap();
            reader.metadata(fixture.canonical_child).unwrap().is_some()
        }));
        assert!(plan.commits().iter().any(|commit| {
            let mut blobs = commit.fragment.blobs().clone();
            let reader = blobs.reader().unwrap();
            reader.metadata(fixture.metadata_root).unwrap().is_some()
                && reader.metadata(fixture.metadata_child).unwrap().is_some()
        }));
    }

    #[test]
    fn retired_mail_evidence_rejects_extra_facts_and_partial_or_multiple_shapes() {
        let fixture = fixture();
        let frozen = &fixture.source;

        let canonical_only = fixture.source_facts.difference(&fixture.retired_facts);
        let absent = validate_retired_mail_evidence(frozen.reader(), &canonical_only).unwrap();
        assert!(absent.facts.is_empty());
        assert!(absent.box_handle.is_none());

        let mut extra = fixture.source_facts.clone();
        extra += entity! { ExclusiveId::force_ref(&fixture.retired_account) @
            schema::grant_object: &Id::new([0x71; 16]).unwrap(),
        }
        .into_facts();
        let error = validate_retired_mail_evidence(frozen.reader(), &extra).unwrap_err();
        assert!(format!("{error:#}").contains("not one exact four-fact record"));

        let partial = fixture.source_facts.difference(&fixture.retired_facts);
        let mut account_only = partial;
        account_only += entity_facts(&fixture.retired_facts, fixture.retired_account);
        let error = validate_retired_mail_evidence(frozen.reader(), &account_only).unwrap_err();
        assert!(format!("{error:#}").contains("exactly one account and one active pointer"));

        let active_facts = entity_facts(&fixture.retired_facts, fixture.retired_active);
        let mut mismatch = fixture.source_facts.difference(&active_facts);
        mismatch +=
            retired_active_record(fixture.retired_active, at(1), "other@example.test").into_facts();
        let error = validate_retired_mail_evidence(frozen.reader(), &mismatch).unwrap_err();
        assert!(format!("{error:#}").contains("without an account record"));

        let second = Id::new([0x72; 16]).unwrap();
        let mut multiple = fixture.source_facts.clone();
        multiple +=
            retired_account_record(second, at(1), "archive@example.test", fixture.retired_box)
                .into_facts();
        let error = validate_retired_mail_evidence(frozen.reader(), &multiple).unwrap_err();
        assert!(format!("{error:#}").contains("found 2 account and 1 active records"));
    }

    #[test]
    fn retired_mail_envelope_must_contain_complete_cryptographic_framing() {
        let fixture = fixture();
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        let short = pile
            .put::<blobencodings::RawBytes, _>(vec![0xA5; 55])
            .unwrap();
        let reader = pile.reader().unwrap();
        let account = Id::new([0x73; 16]).unwrap();
        let active = Id::new([0x74; 16]).unwrap();
        let mut facts =
            retired_account_record(account, at(1), "short@example.test", short).into_facts();
        facts += retired_active_record(active, at(1), "short@example.test").into_facts();

        let error = validate_retired_mail_evidence(&reader, &facts).unwrap_err();
        assert!(format!("{error:#}").contains("shorter than its cryptographic framing"));
        drop(reader);
        pile.close().unwrap();
    }

    #[test]
    fn publication_is_idempotent() {
        let fixture = fixture();
        let frozen = &fixture.source;
        let plan = plan(frozen).unwrap();

        let first = publish(frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        let after_first = fs::metadata(&fixture.pile).unwrap().len();
        let second = publish(frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(first, second);
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), after_first);

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection =
            faculties::collection_names::open(pile, schema::DEFAULT_SCOPE_ID, signer);
        let facts = collection.materialize().unwrap();
        assert_eq!(facts, fixture.canonical_facts);
        let reader = collection.storage_mut().reader().unwrap();
        capability::validate_catalog(&reader, &facts).unwrap();
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn publication_resumes_from_an_incomplete_existing_subset() {
        let fixture = fixture();
        let frozen = &fixture.source;
        let plan = plan(frozen).unwrap();

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection =
            faculties::collection_names::open(pile, schema::DEFAULT_SCOPE_ID, signer);
        // Publish only the scope commit, deliberately omitting the identity it
        // references. The raw collection is temporarily not a valid Secrets
        // catalog, as can happen if a process dies partway through migration.
        let partial = collection
            .commit(plan.commits()[1].fragment.clone())
            .unwrap();
        collection.into_storage().close().unwrap();

        let resumed = publish(frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(resumed[1], partial);

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection =
            faculties::collection_names::open(pile, schema::DEFAULT_SCOPE_ID, signer);
        assert_eq!(collection.materialize().unwrap(), fixture.canonical_facts);
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn conflict_with_existing_native_facts_fails_before_append() {
        let fixture = fixture();
        let frozen = &fixture.source;
        let plan = plan(frozen).unwrap();

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection =
            faculties::collection_names::open(pile, schema::DEFAULT_SCOPE_ID, signer);
        let mut conflict = Fragment::empty();
        let other_name = conflict.put("not-alice".to_owned());
        conflict += entity! { ExclusiveId::force_ref(&fixture.identity) @
            metadata::name: other_name,
        };
        collection.commit(conflict).unwrap();
        collection.into_storage().close().unwrap();
        let before = fs::metadata(&fixture.pile).unwrap().len();

        let error = publish(frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap_err();
        assert!(format!("{error:#}").contains("preflight existing native value"));
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), before);
    }

    #[test]
    fn already_native_retired_mail_facts_fail_preflight_before_append() {
        let fixture = fixture();
        let frozen = &fixture.source;
        let plan = plan(frozen).unwrap();

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let pile = open_pile_strict(&fixture.pile).unwrap();
        let mut collection =
            faculties::collection_names::open(pile, schema::DEFAULT_SCOPE_ID, signer);
        collection
            .commit(Fragment::from(fixture.retired_facts.clone()))
            .unwrap();
        collection.into_storage().close().unwrap();
        let before = fs::metadata(&fixture.pile).unwrap().len();

        let error = publish(frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap_err();
        assert!(format!("{error:#}").contains("preflight existing native value"));
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), before);
    }

    #[test]
    fn missing_durable_signer_fails_without_growing_the_pile() {
        let fixture = fixture();
        let frozen = &fixture.source;
        let plan = plan(frozen).unwrap();
        fs::remove_file(&fixture.key).unwrap();
        let before = fs::metadata(&fixture.pile).unwrap().len();

        let error = publish(frozen, &plan, &fixture.pile, Some(&fixture.key)).unwrap_err();
        assert!(format!("{error:#}").contains("load durable signing key"));
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), before);
    }
}
