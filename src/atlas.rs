//! Typed projections over the additive Atlas metadata collection.
//!
//! Atlas facts are schema evidence rather than mutable scalar state. Multiple
//! names or descriptions therefore remain visible variants; a reader must not
//! let query iteration order manufacture one winning label. Ordinary readers
//! ask for the projection they need directly; the strict whole-value validator
//! at the bottom of this module is reserved for explicit migration/tests.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, Result};
use triblespace::core::blob::Blob;
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::blobencodings::{UTF8String, WasmCode};
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;

pub type TextHandle = Inline<Handle<UTF8String>>;

/// All inspectable metadata attached to one named Atlas entity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtlasEntry {
    pub id: Id,
    pub names: Vec<String>,
    pub descriptions: Vec<String>,
    pub source_modules: Vec<String>,
    pub tags: Vec<Id>,
    /// Every entity carrying this entry as a tag.
    pub members: Vec<Id>,
}

impl AtlasEntry {
    /// A lossless compact label: every name variant participates.
    pub fn names_label(&self) -> String {
        self.names.join(" / ")
    }
}

fn read_text<R: BlobStoreGet>(
    reader: &R,
    handle: TextHandle,
    field: &str,
    id: Id,
) -> Result<String> {
    let value: anybytes::View<str> = reader
        .get(handle)
        .map_err(|error| anyhow!("read Atlas {field} for {id:x}: {error:?}"))?;
    Ok(value.to_string())
}

fn read_text_variants<R: BlobStoreGet>(
    reader: &R,
    handles: BTreeSet<TextHandle>,
    field: &str,
    id: Id,
) -> Result<Vec<String>> {
    handles
        .into_iter()
        .map(|handle| read_text(reader, handle, field, id))
        .collect::<Result<BTreeSet<_>>>()
        .map(|values| values.into_iter().collect())
}

/// Strictly read every Atlas attachment whose encoding is known here.
pub fn validate_known_payloads<R: BlobStoreGet>(reader: &R, facts: &TribleSet) -> Result<()> {
    let text_attributes = [
        metadata::name.id(),
        metadata::description.id(),
        metadata::iri.id(),
        metadata::source.id(),
        metadata::source_module.id(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();

    for fact in facts {
        if text_attributes.contains(fact.a()) {
            let handle = *fact.v::<Handle<UTF8String>>();
            let _: anybytes::View<str> = reader.get(handle).map_err(|error| {
                anyhow!(
                    "read Atlas text payload {}: {error:?}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        } else if fact.a() == &metadata::value_formatter.id() {
            let handle = *fact.v::<Handle<WasmCode>>();
            let _: Blob<WasmCode> = reader.get(handle).map_err(|error| {
                anyhow!(
                    "read Atlas value formatter {}: {error:?}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

/// Project every named Atlas entity needed by a list-style consumer.
///
/// Names and descriptions are intentionally vectors. Atlas is additive and
/// has no causal register that could justify collapsing several values to one.
/// This is a typed query result, not an ambient catalog: unrelated and
/// undecodable open-world facts do not participate.
pub fn named_entries<R, P>(reader: &R, facts: &P) -> Result<Vec<AtlasEntry>>
where
    R: BlobStoreGet,
    P: TriblePattern,
{
    let mut name_handles = BTreeMap::<Id, BTreeSet<TextHandle>>::new();
    for (id, handle) in find!(
        (id: Id, handle: TextHandle),
        pattern!(facts, [{ ?id @ metadata::name: ?handle }])
    ) {
        name_handles.entry(id).or_default().insert(handle);
    }

    let mut description_handles = BTreeMap::<Id, BTreeSet<TextHandle>>::new();
    for (id, handle) in find!(
        (id: Id, handle: TextHandle),
        pattern!(facts, [{ ?id @ metadata::description: ?handle }])
    ) {
        description_handles.entry(id).or_default().insert(handle);
    }

    let mut source_module_handles = BTreeMap::<Id, BTreeSet<TextHandle>>::new();
    for (id, handle) in find!(
        (id: Id, handle: TextHandle),
        pattern!(facts, [{ ?id @ metadata::source_module: ?handle }])
    ) {
        source_module_handles.entry(id).or_default().insert(handle);
    }

    let mut tags = BTreeMap::<Id, BTreeSet<Id>>::new();
    let mut members = BTreeMap::<Id, BTreeSet<Id>>::new();
    for (entity, tag) in find!(
        (entity: Id, tag: Id),
        pattern!(facts, [{ ?entity @ metadata::tag: ?tag }])
    ) {
        tags.entry(entity).or_default().insert(tag);
        members.entry(tag).or_default().insert(entity);
    }

    let mut entries = Vec::with_capacity(name_handles.len());
    for (id, handles) in name_handles {
        let names = read_text_variants(reader, handles, "name", id)?;
        let descriptions = read_text_variants(
            reader,
            description_handles.remove(&id).unwrap_or_default(),
            "description",
            id,
        )?;
        let source_modules = read_text_variants(
            reader,
            source_module_handles.remove(&id).unwrap_or_default(),
            "source module",
            id,
        )?;
        entries.push(AtlasEntry {
            id,
            names,
            descriptions,
            source_modules,
            tags: tags.remove(&id).unwrap_or_default().into_iter().collect(),
            members: members
                .remove(&id)
                .unwrap_or_default()
                .into_iter()
                .collect(),
        });
    }
    Ok(entries)
}

/// Project one named Atlas entity without constructing the list projection.
///
/// `None` means this read type sees no name for `id`. Other facts on the same
/// opaque id remain valid open-world data and are deliberately ignored.
pub fn named_entry<R, P>(reader: &R, facts: &P, id: Id) -> Result<Option<AtlasEntry>>
where
    R: BlobStoreGet,
    P: TriblePattern,
{
    let names = read_text_variants(
        reader,
        find!(
            handle: TextHandle,
            pattern!(facts, [{ id @ metadata::name: ?handle }])
        )
        .collect(),
        "name",
        id,
    )?;
    if names.is_empty() {
        return Ok(None);
    }

    let descriptions = read_text_variants(
        reader,
        find!(
            handle: TextHandle,
            pattern!(facts, [{ id @ metadata::description: ?handle }])
        )
        .collect(),
        "description",
        id,
    )?;
    let source_modules = read_text_variants(
        reader,
        find!(
            handle: TextHandle,
            pattern!(facts, [{ id @ metadata::source_module: ?handle }])
        )
        .collect(),
        "source module",
        id,
    )?;
    let tags = find!(
        tag: Id,
        pattern!(facts, [{ id @ metadata::tag: ?tag }])
    )
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect();
    let members = find!(
        member: Id,
        pattern!(facts, [{ ?member @ metadata::tag: id }])
    )
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect();

    Ok(Some(AtlasEntry {
        id,
        names,
        descriptions,
        source_modules,
        tags,
        members,
    }))
}

/// Validate one explicit stopped-world Atlas candidate.
///
/// Normal readers must use [`named_entries`] or [`named_entry`] instead: this
/// full scan exists only for migration and adversarial-boundary tests.
pub fn validate_catalog<R: BlobStoreGet>(reader: &R, facts: &TribleSet) -> Result<()> {
    validate_known_payloads(reader, facts)?;
    named_entries(reader, facts).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_preserves_every_name_and_description_variant() {
        let id = Id::new([0x41; 16]).unwrap();
        let member = Id::new([0x42; 16]).unwrap();
        let mut fragment = Fragment::empty();
        let alpha = fragment.put::<UTF8String, _>("Alpha".to_owned());
        let beta = fragment.put::<UTF8String, _>("Beta".to_owned());
        let first = fragment.put::<UTF8String, _>("First description".to_owned());
        let second = fragment.put::<UTF8String, _>("Second description".to_owned());
        fragment += entity! { ExclusiveId::force_ref(&id) @
            metadata::name: beta,
            metadata::description: second,
        };
        fragment += entity! { ExclusiveId::force_ref(&id) @
            metadata::name: alpha,
            metadata::description: first,
        };
        fragment += entity! { ExclusiveId::force_ref(&member) @ metadata::tag: &id };

        let mut blobs = fragment.blobs().clone();
        let reader = blobs.snapshot().unwrap();
        let entries = named_entries(&reader, fragment.facts()).unwrap();
        let entry = entries.iter().find(|entry| entry.id == id).unwrap();

        assert_eq!(entry.names, ["Alpha", "Beta"]);
        assert_eq!(
            entry.descriptions,
            ["First description", "Second description"]
        );
        assert_eq!(entry.members, [member]);

        assert_eq!(
            named_entry(&reader, fragment.facts(), id).unwrap(),
            Some(entry.clone())
        );
    }

    #[test]
    fn ordinary_projection_ignores_unrequested_open_world_payloads() {
        let named = Id::new([0x51; 16]).unwrap();
        let unrelated = Id::new([0x52; 16]).unwrap();
        let mut fragment = Fragment::empty();
        let name = fragment.put::<UTF8String, _>("Readable".to_owned());
        fragment += entity! { ExclusiveId::force_ref(&named) @ metadata::name: name };
        fragment += entity! { ExclusiveId::force_ref(&unrelated) @
            metadata::value_formatter: Inline::<Handle<WasmCode>>::new([0x53; 32]),
        };

        let mut blobs = fragment.blobs().clone();
        let reader = blobs.snapshot().unwrap();
        let entries = named_entries(&reader, fragment.facts()).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, named);
        assert!(validate_catalog(&reader, fragment.facts()).is_err());
    }
}
