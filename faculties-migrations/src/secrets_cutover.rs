//! Bounded stopped-world migration of the legacy Secrets branch.
//!
//! The historical branch contains canonical Secrets facts alongside a retired
//! four-fact Mail-account record and three-fact active pointer vocabulary.
//! Planning validates that bounded partition and returns only the retained v1
//! catalog needed by the direct v2 vault projection. The original bytes,
//! authored partitions, and provenance already remain in the copied prefix;
//! they are not rebuilt as an intermediary native collection.

use std::collections::BTreeSet;

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::attribute::Attribute;
use triblespace::core::inline::{Inline, InlineEncoding};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::*;

use crate::collection_cutover::{FrozenSource, LegacyPinCoordinate};
use faculties::secrets::{self as capability, schema};

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

/// Conservation summary for a complete Secrets migration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SecretsMigrationReport {
    /// Exact fact count at the verified legacy branch head.
    pub source_facts: usize,
    /// Retained canonical v1 Secrets facts projected directly into v2 vaults.
    pub facts: usize,
    /// Exact historical Mail facts validated and deliberately not projected.
    pub retired_facts: usize,
}

/// Minimal pure boundary between the frozen branch and direct v2 planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretsMigrationPlan {
    source_pin: LegacyPinCoordinate,
    retained: TribleSet,
    retired: TribleSet,
    report: SecretsMigrationReport,
}

impl SecretsMigrationPlan {
    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub fn retained_facts(&self) -> &TribleSet {
        &self.retained
    }

    /// Exact bounded evidence omitted from native Secrets authority.
    pub fn retired_facts(&self) -> &TribleSet {
        &self.retired
    }

    pub const fn report(&self) -> &SecretsMigrationReport {
        &self.report
    }

    /// Recheck the exact bounded partition independently of direct planning.
    pub fn verify_conservation(&self) -> Result<()> {
        if !self.retained.intersect(&self.retired).is_empty() {
            bail!("retained Secrets facts overlap retired Mail evidence");
        }
        if self.report.source_facts != self.retained.len() + self.retired.len()
            || self.report.facts != self.retained.len()
            || self.report.retired_facts != self.retired.len()
        {
            bail!("Secrets migration report disagrees with its bounded partition");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RetiredMailEvidence {
    facts: TribleSet,
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

    Ok(RetiredMailEvidence { facts: retired })
}

/// Validate and partition the complete named legacy Secrets branch without
/// mutating its pile or reconstructing its authored partitions.
pub fn plan(source: &FrozenSource) -> Result<SecretsMigrationPlan> {
    let branch = source
        .legacy_branch(schema::LEGACY_BRANCH_NAME)?
        .ok_or_else(|| anyhow!("frozen source has no legacy Secrets branch"))?;
    let source_pin = branch.pin_coordinate();
    let source_facts = branch
        .deltas
        .iter()
        .filter(|delta| delta.is_authored())
        .fold(TribleSet::new(), |mut all, delta| {
            all += delta.facts.clone();
            all
        });
    let retired = validate_retired_mail_evidence(source.reader(), &source_facts)
        .context("validate bounded retired Mail evidence on legacy Secrets branch")?;
    let retained = source_facts.difference(&retired.facts);

    // Retired Mail evidence never enters the v1 validator and therefore
    // cannot acquire Secrets authorization merely by sharing the old branch.
    capability::validate_catalog(source.reader(), &retained)
        .context("validate complete retained legacy Secrets catalog")?;

    let plan = SecretsMigrationPlan {
        source_pin,
        report: SecretsMigrationReport {
            source_facts: source_facts.len(),
            facts: retained.len(),
            retired_facts: retired.facts.len(),
        },
        retained,
        retired: retired.facts,
    };
    plan.verify_conservation()?;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use triblespace::core::repo::BlobStore;

    use super::*;
    use crate::collection_cutover::test_support::{TestBranchSpec, TestDeltaSpec, TestSourceSpec};
    use faculties::storage::{initialize_signer, open_pile_strict};

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
        identity: Id,
        scope: Id,
        source_facts: TribleSet,
        canonical_facts: TribleSet,
        retired_facts: TribleSet,
        retired_account: Id,
        retired_active: Id,
        retired_box: BytesHandle,
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
            identity,
            scope,
            source_facts,
            canonical_facts,
            retired_facts,
            retired_account,
            retired_active,
            retired_box,
            source,
        }
    }

    #[test]
    fn plan_returns_only_the_bounded_partition_for_direct_projection() {
        let fixture = fixture();
        let frozen = &fixture.source;
        let plan = plan(frozen).unwrap();

        plan.verify_conservation().unwrap();
        assert_eq!(plan.retained_facts(), &fixture.canonical_facts);
        assert_eq!(plan.retired_facts(), &fixture.retired_facts);
        assert_eq!(plan.report().source_facts, fixture.source_facts.len());
        assert_eq!(plan.report().facts, fixture.canonical_facts.len());
        assert_eq!(plan.report().retired_facts, fixture.retired_facts.len());
        assert!(plan
            .retained_facts()
            .iter()
            .any(|fact| fact.e() == &fixture.identity));
        assert!(plan
            .retained_facts()
            .iter()
            .any(|fact| fact.e() == &fixture.scope));
        assert!(plan
            .retained_facts()
            .iter()
            .all(|fact| fact.e() != &fixture.retired_account));
    }

    #[test]
    fn retired_mail_evidence_rejects_extra_facts_and_partial_or_multiple_shapes() {
        let fixture = fixture();
        let frozen = &fixture.source;

        let canonical_only = fixture.source_facts.difference(&fixture.retired_facts);
        let absent = validate_retired_mail_evidence(frozen.reader(), &canonical_only).unwrap();
        assert!(absent.facts.is_empty());

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
}
