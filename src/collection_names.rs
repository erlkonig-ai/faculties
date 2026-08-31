//! Canonical root descriptors for faculty collections.
//!
//! A root collection used to be anchored by an opaque minted scope id. It
//! discriminated roots correctly and told a reader nothing: the id lived as a
//! hex constant in one faculty's source, so "which collection is this?" was
//! answerable only by someone holding the code. A root is now a self-describing
//! fragment containing its name, representation, and immutable READ and WRITE
//! admission policies. The fragment's content handle is the collection
//! identity.
//!
//! The scope ids have not gone anywhere — they remain each schema's stable
//! identifier and the key this table is read by, because the migration that
//! re-seats existing data has to speak both languages at once.

use std::ffi::OsString;

use anybytes::View;
use anyhow::{anyhow, bail, Context};
use ed25519_dalek::VerifyingKey;

use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::utf8string::UTF8String;
use triblespace::core::blob::{Blob, TryFromBlob};
use triblespace::core::collection::{
    descriptor, records::CollectionHandle, AdmissionPolicy, Collection, CollectionPolicy,
    CollectionRegistrationError, CollectionStoreExt,
};
use triblespace::core::id::Id;
use triblespace::core::inline::Inline;
use triblespace::core::repo::{BlobStoreGet, BlobStorePut, CapabilityProofRead, SnapshotSource};
use triblespace::core::trible::TribleSet;

use crate::schemas::{
    atlas, blockdag, body, cognition, compass, decide, discord, embeddings, files, habit,
    headspace, mail, memory, message, orient, planner, posture, relations, status, teams, voice,
    web, wiki,
};

/// Every root collection this build writes: the scope that used to anchor it,
/// and the name it is known by.
///
/// A faculty that is missing here cannot be opened at all, which is the point:
/// a nameless collection is one the pile cannot describe, and shipping one
/// silently is how the old scope model stayed opaque for so long. Every
/// collection in this table deliberately uses a direct READ and WRITE policy
/// rooted at the pile's durable signer. Sharing a collection later means
/// creating or migrating to a descriptor whose policy says so; it is not an
/// ambient property hidden in this table.
///
/// The ones worth naming individually:
///
/// - `memory` and `memory-comb` are the journal, first-person and personal.
/// - `compass` and `wiki` are the two JP has floated sharing. Neither becomes
///   public here: his own design for compass is a collection that shares its
///   goals but not the personal notes attached to them, which is *two*
///   collections, not one made public. A public sibling is the shape, with its
///   own explicit admission policy.
pub fn table() -> Vec<(Id, &'static str)> {
    vec![
        (atlas::DEFAULT_SCOPE_ID, "atlas"),
        (blockdag::DEFAULT_SCOPE_ID, "blockdag"),
        (body::DEFAULT_SCOPE_ID, "body"),
        (cognition::DEFAULT_SCOPE_ID, "cognition"),
        (compass::DEFAULT_SCOPE_ID, "compass"),
        (decide::DEFAULT_SCOPE_ID, "decide"),
        (discord::DEFAULT_SCOPE_ID, "discord"),
        (embeddings::DEFAULT_SCOPE_ID, "embeddings"),
        (files::DEFAULT_SCOPE_ID, "files"),
        (habit::DEFAULT_SCOPE_ID, "habit"),
        (headspace::DEFAULT_SCOPE_ID, "headspace"),
        (mail::DEFAULT_SCOPE_ID, "mail"),
        (memory::DEFAULT_SCOPE_ID, "memory-journal"),
        (memory::DEFAULT_COMB_SCOPE_ID, "memory-comb"),
        (message::DEFAULT_SCOPE_ID, "message"),
        (orient::DEFAULT_SCOPE_ID, "orient"),
        (planner::DEFAULT_SCOPE_ID, "planner"),
        (posture::DEFAULT_POLICY_SCOPE_ID, "posture-policy"),
        (posture::DEFAULT_SCAN_SCOPE_ID, "posture-scan"),
        (relations::DEFAULT_SCOPE_ID, "relations"),
        (status::DEFAULT_SCOPE_ID, "status"),
        (teams::DEFAULT_SCOPE_ID, "teams"),
        (voice::COLLECTION_SCOPE_ID, "voice"),
        (web::DEFAULT_SCOPE_ID, "web"),
        (wiki::DEFAULT_SCOPE_ID, "wiki"),
    ]
}

/// The name for one scope, or `None` if this build does not know it.
pub fn name_for(scope: Id) -> Option<&'static str> {
    table()
        .into_iter()
        .find(|(candidate, _)| *candidate == scope)
        .map(|(_, name)| name)
}

/// The name for one scope, or a panic naming the scope that is missing.
///
/// Every collection this build opens is one it wrote the table entry for, so an
/// absence is a bug in this crate rather than anything a pile can cause. It is
/// loud because the alternative — inventing a name — would root real data at a
/// collection nothing else can find.
pub fn require_name(scope: Id) -> &'static str {
    name_for(scope).unwrap_or_else(|| {
        panic!(
            "no collection name for scope {scope:X}; add it to \
             faculties::collection_names::table"
        )
    })
}

/// The private policy deliberately shared by every current faculty root.
pub fn private_policy(authority: VerifyingKey) -> CollectionPolicy {
    CollectionPolicy::new(
        AdmissionPolicy::direct(authority),
        AdmissionPolicy::direct(authority),
    )
}

/// Prefix for exact descriptor overrides understood by every faculty.
///
/// The suffix is the canonical collection name, uppercased with `-` replaced
/// by `_`: `wiki` is `TRIBLESPACE_COLLECTION_WIKI`, while `memory-journal` is
/// `TRIBLESPACE_COLLECTION_MEMORY_JOURNAL`. Keeping one variable per name lets
/// a process which reads several faculty collections select each one
/// independently instead of applying one ambient collection identity to all
/// of them.
pub const COLLECTION_OVERRIDE_PREFIX: &str = "TRIBLESPACE_COLLECTION_";

/// Deterministic environment-variable name for one faculty collection.
pub fn override_env_name(scope: Id) -> String {
    let name = require_name(scope);
    let mut variable = String::with_capacity(COLLECTION_OVERRIDE_PREFIX.len() + name.len());
    variable.push_str(COLLECTION_OVERRIDE_PREFIX);
    variable.extend(name.bytes().map(|byte| match byte {
        b'a'..=b'z' => char::from(byte - b'a' + b'A'),
        b'A'..=b'Z' | b'0'..=b'9' => char::from(byte),
        b'-' => '_',
        _ => panic!("collection name {name:?} cannot form an environment variable"),
    }));
    variable
}

fn parse_override(variable: &str, raw: OsString) -> anyhow::Result<CollectionHandle> {
    let raw = raw
        .into_string()
        .map_err(|_| anyhow!("{variable} is not valid UTF-8"))?;
    let raw = raw.trim();
    let raw = raw.strip_prefix("blake3:").unwrap_or(raw);
    if raw.len() != 64 {
        bail!("{variable} must be one exact 64-digit hexadecimal collection descriptor handle");
    }
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(raw, &mut bytes)
        .with_context(|| format!("{variable} is not a hexadecimal collection descriptor handle"))?;
    Ok(Inline::new(bytes))
}

/// Exact descriptor override selected for `scope`, if the operator supplied
/// one.
///
/// Invalid values fail loudly. Falling back to a signer-private descriptor in
/// that case would silently fork a shared collection into a different identity.
pub fn configured_handle(scope: Id) -> anyhow::Result<Option<CollectionHandle>> {
    let variable = override_env_name(scope);
    std::env::var_os(&variable)
        .map(|raw| parse_override(&variable, raw))
        .transpose()
}

/// Open the operator-selected exact descriptor, or construct the ordinary
/// signer-private faculty descriptor when no override is present.
///
/// The override path is non-registering: its canonical descriptor must already
/// be resident, carry the name assigned to this faculty scope, and admit the
/// caller's signer under its WRITE policy. Failing before a command can append
/// an inert COMMIT keeps a mistyped handle or missing grant from looking like a
/// successful faculty write.
pub fn open_configured<S>(
    storage: &mut S,
    scope: Id,
    authority: VerifyingKey,
) -> anyhow::Result<Collection<SimpleArchive>>
where
    S: CollectionStoreExt + SnapshotSource,
    <S as SnapshotSource>::Snapshot: BlobStoreGet + CapabilityProofRead,
{
    let Some(handle) = configured_handle(scope)? else {
        return open(storage, scope, authority).context("register signer-private descriptor");
    };

    let snapshot = storage
        .snapshot()
        .context("freeze store while opening configured collection descriptor")?;
    open_exact_in(&snapshot, scope, authority, handle)
}

/// Open and validate one exact faculty descriptor in an existing snapshot.
///
/// This is the coherent read-boundary form used by callers which already froze
/// a pile prefix. It validates the descriptor's type and faculty name, then
/// proves that `authority` may publish before any later command can append an
/// inert COMMIT.
pub fn open_exact_in<S>(
    snapshot: &S,
    scope: Id,
    authority: VerifyingKey,
    handle: CollectionHandle,
) -> anyhow::Result<Collection<SimpleArchive>>
where
    S: BlobStoreGet + CapabilityProofRead,
{
    let collection = Collection::open(snapshot, handle).with_context(|| {
        format!(
            "open exact {} descriptor from {}",
            require_name(scope),
            override_env_name(scope)
        )
    })?;
    let blob: Blob<SimpleArchive> = snapshot
        .get(handle)
        .context("read configured collection descriptor while checking its name")?;
    let facts = TribleSet::try_from_blob(blob)
        .context("decode configured collection descriptor while checking its name")?;
    let name_handle = descriptor::name(&facts)
        .context("decode configured collection name")?
        .ok_or_else(|| anyhow!("configured faculty collection is derived and has no root name"))?;
    let name: View<str> = snapshot
        .get::<View<str>, UTF8String>(name_handle)
        .context("read configured collection name")?;
    let expected = require_name(scope);
    if &*name != expected {
        bail!(
            "{} names collection {:?}, not expected faculty collection {:?}",
            override_env_name(scope),
            &*name,
            expected,
        );
    }
    if !collection
        .writer_is_admitted(snapshot, authority)
        .context("check configured collection WRITE admission")?
    {
        bail!(
            "durable signer {} is not admitted to WRITE configured collection {:?}",
            hex::encode(authority.to_bytes()),
            expected,
        );
    }
    Ok(collection)
}

/// Register one faculty root and return its typed descriptor handle.
///
/// Registration is idempotent and owns the descriptor's complete attachment
/// closure. Later publication and snapshots take only the returned handle;
/// the store remains owned by its caller.
pub fn open<S>(
    storage: &mut S,
    scope: Id,
    authority: VerifyingKey,
) -> Result<Collection<SimpleArchive>, CollectionRegistrationError<<S as BlobStorePut>::PutError>>
where
    S: CollectionStoreExt,
{
    storage.collection(require_name(scope), private_policy(authority))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use ed25519_dalek::SigningKey;
    use triblespace::core::collection::grant_collection_write;
    use triblespace::core::metadata;
    use triblespace::core::repo::memoryrepo::MemoryRepo;
    use triblespace::core::repo::SnapshotSource;
    use triblespace::core::trible::TribleSet;
    use triblespace::macros::entity;

    #[test]
    fn every_name_is_nonempty_and_no_two_scopes_share_one() {
        let mut names = BTreeSet::new();
        let mut scopes = BTreeSet::new();
        let mut variables = BTreeSet::new();
        for (scope, name) in table() {
            assert!(!name.is_empty());
            assert!(names.insert(name), "two scopes both claim the name {name}");
            assert!(scopes.insert(scope), "scope {scope:X} appears twice");
            assert!(
                variables.insert(override_env_name(scope)),
                "two collections normalize to one override variable"
            );
        }
    }

    #[test]
    fn a_scope_with_no_name_is_loud_rather_than_invented() {
        assert!(name_for(Id::new([0x5a; 16]).unwrap()).is_none());
    }

    #[test]
    fn root_policy_is_identity_and_snapshot_admission() {
        let local = SigningKey::from_bytes(&[0x31; 32]);
        let foreign = SigningKey::from_bytes(&[0x73; 32]);
        let scope = wiki::DEFAULT_SCOPE_ID;
        let evidence = entity! { _ @ metadata::tag: &scope };
        let expected = evidence.facts().clone();
        let mut store = MemoryRepo::default();
        let collection = open(&mut store, scope, local.verifying_key()).unwrap();
        store
            .commit(collection, &foreign, evidence.clone())
            .unwrap();
        let store_snapshot = store.snapshot().unwrap();
        let facts = collection.read::<TribleSet, _>(&store_snapshot).unwrap();
        assert!(facts.is_empty());

        store.commit(collection, &local, evidence).unwrap();
        let store_snapshot = store.snapshot().unwrap();
        let facts = collection.read::<TribleSet, _>(&store_snapshot).unwrap();
        assert!(expected.difference(&facts).is_empty());
    }

    #[test]
    fn override_names_and_handles_are_exact() {
        assert_eq!(
            override_env_name(memory::DEFAULT_SCOPE_ID),
            "TRIBLESPACE_COLLECTION_MEMORY_JOURNAL"
        );
        let variable = override_env_name(wiki::DEFAULT_SCOPE_ID);
        let raw = "ab".repeat(32);
        assert_eq!(
            parse_override(&variable, OsString::from(&raw)).unwrap().raw,
            [0xab; 32]
        );
        assert_eq!(
            parse_override(&variable, OsString::from(format!("blake3:{raw}")))
                .unwrap()
                .raw,
            [0xab; 32]
        );
        assert!(parse_override(&variable, OsString::from("ab")).is_err());
        assert!(parse_override(&variable, OsString::from("zz".repeat(32))).is_err());
    }

    #[test]
    fn exact_open_requires_the_expected_name_and_write_admission() {
        let operator = SigningKey::from_bytes(&[0x41; 32]);
        let tenant = SigningKey::from_bytes(&[0x52; 32]);
        let mut store = MemoryRepo::default();
        let shared = store
            .collection("wiki", private_policy(operator.verifying_key()))
            .unwrap();
        let snapshot = store.snapshot().unwrap();
        let opened = open_exact_in(
            &snapshot,
            wiki::DEFAULT_SCOPE_ID,
            operator.verifying_key(),
            shared.handle(),
        )
        .unwrap();
        assert_eq!(opened, shared);
        assert!(open_exact_in(
            &snapshot,
            wiki::DEFAULT_SCOPE_ID,
            tenant.verifying_key(),
            shared.handle(),
        )
        .unwrap_err()
        .to_string()
        .contains("is not admitted to WRITE"));
        drop(snapshot);

        grant_collection_write(
            &mut store,
            shared.handle(),
            &operator,
            tenant.verifying_key(),
        )
        .unwrap();
        let snapshot = store.snapshot().unwrap();
        let opened = open_exact_in(
            &snapshot,
            wiki::DEFAULT_SCOPE_ID,
            tenant.verifying_key(),
            shared.handle(),
        )
        .unwrap();
        let private = open(&mut store, wiki::DEFAULT_SCOPE_ID, tenant.verifying_key()).unwrap();

        assert_eq!(opened, shared);
        assert_ne!(opened, private);

        let wrong_name = store
            .collection("relations", private_policy(tenant.verifying_key()))
            .unwrap();
        let snapshot = store.snapshot().unwrap();
        let error = open_exact_in(
            &snapshot,
            wiki::DEFAULT_SCOPE_ID,
            tenant.verifying_key(),
            wrong_name.handle(),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("not expected faculty collection"));
    }
}
