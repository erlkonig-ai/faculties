//! Frozen reader for the retired enumerable collection-authority generation.
//!
//! This is deliberately migration-only and root-directed. It reconstructs the
//! one known durable signer's canonical historical authority collection and
//! inspects only strictly verified commits authored by that root. It never
//! enumerates foreign authority roots or restores ambient authority to current
//! runtime code.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::{Blob, IntoBlob, TryFromBlob};
use triblespace::core::collection::{
    descriptor, discover_collection_records_scoped, empty_metadata_handle, reach,
    simplearchive_union, CollectionHandle, CollectionName,
};
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStore, BlobStoreGet};
use triblespace::prelude::*;

use faculties::secrets;

const AUTHORITY_COLLECTION_NAME: &str = "authority";
const KIND_AUTHORITY_GRANT: Id = triblespace::macros::id_hex!("411A564F0ED4EA6B577C9F9E2B492600");

attributes! {
    // Published by the retired authority protocol. These are its original
    // minted anchors; the encoding remains part of each attribute identity.
    "194BCB6BD8F229EBF43028F7E6818144" as authority_subject:
        inlineencodings::ED25519PublicKey;
    "40E42C8164A930E19231AE8E3B647FB3" as authority_resource:
        inlineencodings::Handle<blobencodings::SimpleArchive>;
    "06FFCE24DE393E3F03160341C9EBE9FC" as authority_action:
        inlineencodings::GenId;
    "CA3AF10504A5DB286A8E5276B1451CE7" as authority_parent:
        inlineencodings::GenId;
    "BFD270009322755EDE43BBD9E2DAA400" as authority_invoke:
        inlineencodings::Boolean;
    "032A475D8C019F1548995D899D9425B1" as authority_delegate:
        inlineencodings::Boolean;
}

#[derive(Clone, Copy)]
struct LegacyGrant {
    parent: Option<Id>,
    subject: VerifyingKey,
    resource: CollectionHandle,
    action: Id,
    invoke: bool,
}

fn exactly_one<T>(values: impl IntoIterator<Item = T>, field: &str) -> Result<T> {
    let mut values = values.into_iter();
    let value = values
        .next()
        .ok_or_else(|| anyhow!("legacy authority grant is missing {field}"))?;
    if values.next().is_some() {
        bail!("legacy authority grant repeats {field}");
    }
    Ok(value)
}

fn at_most_one<T>(values: impl IntoIterator<Item = T>, field: &str) -> Result<Option<T>> {
    let mut values = values.into_iter();
    let value = values.next();
    if values.next().is_some() {
        bail!("legacy authority grant repeats {field}");
    }
    Ok(value)
}

fn grant_fragment(
    subject: VerifyingKey,
    resource: CollectionHandle,
    action: Id,
    parent: Option<Id>,
    invoke: bool,
    delegate: bool,
) -> Fragment {
    let subject = Inline::<inlineencodings::ED25519PublicKey>::new(subject.to_bytes());
    let built = entity! {
        metadata::tag: KIND_AUTHORITY_GRANT,
        authority_subject: subject,
        authority_resource: resource,
        authority_action: action,
        authority_parent?: parent,
        authority_invoke: invoke,
        authority_delegate: delegate,
    };
    let root = built
        .root()
        .expect("one intrinsic retired authority entity exports one root");
    // Historical authority commits deliberately stripped the descriptions
    // carried by anchored attributes and signed empty metadata.
    Fragment::rooted(root, built.into_facts())
}

fn decode_grant(facts: &TribleSet) -> Result<LegacyGrant> {
    let entity = exactly_one(
        find!(
            (entity: Id),
            pattern!(facts, [{ ?entity @ metadata::tag: KIND_AUTHORITY_GRANT }])
        )
        .map(|(entity,)| entity),
        "metadata::tag",
    )?;
    let subject = exactly_one(
        find!(
            (value: Inline<inlineencodings::ED25519PublicKey>),
            pattern!(facts, [{ entity @ authority_subject: ?value }])
        )
        .map(|(value,)| value),
        "authority_subject",
    )?;
    let subject = VerifyingKey::from_bytes(&subject.raw)
        .context("legacy authority grant has an invalid subject key")?;
    let resource = exactly_one(
        find!(
            (value: CollectionHandle),
            pattern!(facts, [{ entity @ authority_resource: ?value }])
        )
        .map(|(value,)| value),
        "authority_resource",
    )?;
    let action = exactly_one(
        find!(
            (value: Inline<inlineencodings::GenId>),
            pattern!(facts, [{ entity @ authority_action: ?value }])
        )
        .map(|(value,)| value),
        "authority_action",
    )?
    .try_from_inline::<Id>()
    .map_err(|_| anyhow!("legacy authority grant has an invalid action id"))?;
    let parent = at_most_one(
        find!(
            (value: Inline<inlineencodings::GenId>),
            pattern!(facts, [{ entity @ authority_parent: ?value }])
        )
        .map(|(value,)| value),
        "authority_parent",
    )?
    .map(|value| {
        value
            .try_from_inline::<Id>()
            .map_err(|_| anyhow!("legacy authority grant has an invalid parent id"))
    })
    .transpose()?;
    let invoke = exactly_one(
        find!(
            (value: Inline<inlineencodings::Boolean>),
            pattern!(facts, [{ entity @ authority_invoke: ?value }])
        )
        .map(|(value,)| value),
        "authority_invoke",
    )?
    .try_from_inline::<bool>()
    .map_err(|_| anyhow!("legacy authority grant has an invalid invoke flag"))?;
    let delegate = exactly_one(
        find!(
            (value: Inline<inlineencodings::Boolean>),
            pattern!(facts, [{ entity @ authority_delegate: ?value }])
        )
        .map(|(value,)| value),
        "authority_delegate",
    )?
    .try_from_inline::<bool>()
    .map_err(|_| anyhow!("legacy authority grant has an invalid delegate flag"))?;
    if !invoke && !delegate {
        bail!("legacy authority grant has empty authority");
    }

    let canonical = grant_fragment(subject, resource, action, parent, invoke, delegate);
    if canonical.root() != Some(entity) || canonical.facts() != facts {
        bail!("legacy authority grant is not one exact canonical grant entity");
    }
    Ok(LegacyGrant {
        parent,
        subject,
        resource,
        action,
        invoke,
    })
}

fn authority_descriptor(root: VerifyingKey) -> Fragment {
    simplearchive_union::descriptor(
        &CollectionName::new(AUTHORITY_COLLECTION_NAME)
            .expect("the retired authority collection name is canonical"),
        root,
        None,
        reach::public(),
    )
}

fn exact_archive(
    reader: &PileReader,
    handle: Inline<Handle<SimpleArchive>>,
    label: &str,
) -> Result<TribleSet> {
    let blob: Blob<SimpleArchive> = reader
        .get(handle)
        .with_context(|| format!("read {label}"))?;
    let blob = Blob::<SimpleArchive>::new(blob.bytes.clone());
    let actual = blob.get_handle();
    if actual != handle {
        bail!("{label} bytes do not match their content handle");
    }
    TribleSet::try_from_blob(blob).with_context(|| format!("decode {label}"))
}

/// Discover canonical retired direct vaults named by the known durable root.
///
/// Production direct Secrets issued root READ to itself at vault creation and
/// exposed no delegated WRITE surface. That exact root grant is the migration
/// inventory. Supporting bespoke delegated historical writers would require a
/// separate explicit migration contract; this helper intentionally does not
/// copy the retired global resolver or enumerate foreign roots.
pub(crate) fn discover_root_direct_vaults<S>(
    store: &mut S,
    signer: &SigningKey,
) -> Result<BTreeMap<Id, CollectionHandle>>
where
    S: BlobStore<Reader = PileReader> + triblespace::core::collection::CollectionStore,
{
    let root = signer.verifying_key();
    let expected_descriptor = authority_descriptor(root);
    let authority = expected_descriptor.facts().clone().to_blob().get_handle();
    let records =
        discover_collection_records_scoped(&mut *store, authority, Inline::new(root.to_bytes()))
            .context("discover strict root-authored retired authority commits")?;
    if records.commits().is_empty() {
        return Ok(BTreeMap::new());
    }

    let reader = store
        .reader()
        .context("open retired authority attachment view")?;
    let descriptor_facts = exact_archive(&reader, authority, "retired authority descriptor")?;
    if descriptor_facts != *expected_descriptor.facts() {
        bail!("retired authority descriptor differs from its canonical root descriptor");
    }

    let empty_metadata = empty_metadata_handle();
    let mut resources = Vec::new();
    for commit in records.commits() {
        if commit.metadata() != empty_metadata {
            bail!("root-authored retired authority commit has nonempty metadata");
        }
        let metadata = exact_archive(
            &reader,
            commit.metadata(),
            "retired authority commit metadata",
        )?;
        if !metadata.is_empty() {
            bail!("root-authored retired authority commit metadata is not empty");
        }
        let data = Handle::<SimpleArchive>::from_hash(commit.data());
        let grant = decode_grant(&exact_archive(
            &reader,
            data,
            "retired authority grant data",
        )?)?;
        if grant.parent.is_none()
            && grant.subject == root
            && grant.action == secrets::ACTION_READ
            && grant.invoke
        {
            resources.push(grant.resource);
        }
    }

    let mut vaults = BTreeMap::new();
    for resource in resources {
        let facts = exact_archive(&reader, resource, "retired direct-vault descriptor")?;
        let name = descriptor::name(&facts)
            .context("retired direct-vault descriptor has no collection name")??;
        let vault = secrets::parse_vault_name(&name)
            .context("retired root READ resource is not a canonical Secrets vault name")?;
        let canonical = simplearchive_union::descriptor(
            &secrets::vault_name(vault),
            root,
            None,
            reach::private(),
        );
        let canonical_handle = canonical.facts().clone().to_blob().get_handle();
        if resource != canonical_handle || facts != *canonical.facts() {
            bail!("retired root READ resource is not an exact canonical direct-vault descriptor");
        }
        if let Some(previous) = vaults.insert(vault, resource) {
            if previous != resource {
                bail!("one retired direct vault id names multiple canonical resources");
            }
        }
    }
    Ok(vaults)
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub fn descriptor(root: VerifyingKey) -> Fragment {
        authority_descriptor(root)
    }

    pub fn root_read_grant(subject: VerifyingKey, resource: CollectionHandle) -> Fragment {
        grant_fragment(subject, resource, secrets::ACTION_READ, None, true, false)
    }

    #[test]
    fn historical_wire_ids_and_bare_authority_descriptor_stay_frozen() {
        assert_eq!(
            authority_subject.id(),
            triblespace::macros::id_hex!("46E97A5EBF4EED84AD33F0B25E05F877")
        );
        assert_eq!(
            authority_resource.id(),
            triblespace::macros::id_hex!("E893BD238216556327E725806DE93DF8")
        );
        assert_eq!(
            authority_action.id(),
            triblespace::macros::id_hex!("B4B58D29528465BDF275378A0F0C21D5")
        );
        assert_eq!(
            authority_parent.id(),
            triblespace::macros::id_hex!("D57B9F560E40951156122D934E08D9B2")
        );
        assert_eq!(
            authority_invoke.id(),
            triblespace::macros::id_hex!("E475AF30EC6025E6882CF35648609C6D")
        );
        assert_eq!(
            authority_delegate.id(),
            triblespace::macros::id_hex!("E06D0D3EFCF5FEB4AD8B51F8E9B5CBBD")
        );

        let root = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let descriptor: Blob<SimpleArchive> = authority_descriptor(root).facts().clone().to_blob();
        let handle = descriptor.get_handle();
        assert_eq!(
            hex::encode_upper(handle.raw),
            "C375E9E047D86CE4F283108491D7B0CFF2E433A1A0CC0522CD0EF7D153887ADF"
        );

        let vault = Id::new([8; 16]).unwrap();
        let resource = simplearchive_union::descriptor(
            &secrets::vault_name(vault),
            root,
            None,
            reach::private(),
        )
        .facts()
        .clone()
        .to_blob()
        .get_handle();
        let grant = grant_fragment(root, resource, secrets::ACTION_READ, None, true, false);
        assert!(grant.metafacts().is_empty());
        assert_eq!(
            grant.root(),
            Some(triblespace::macros::id_hex!(
                "B6A74F5D69F2C477A4C090D419FCBCE0"
            ))
        );
    }
}
