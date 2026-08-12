//! Canonical read model for the additive Atlas metadata catalog.
//!
//! Atlas facts are schema evidence rather than mutable scalar state. Multiple
//! names or descriptions therefore remain visible variants; a reader must not
//! let hash-map insertion order manufacture one winning label.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, Result};
use triblespace::core::blob::Blob;
use triblespace::core::metadata;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::blobencodings::{LongString, WasmCode};
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;

pub type TextHandle = Inline<Handle<LongString>>;

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

/// Deterministic, lossless projection of one complete Atlas value.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AtlasCatalog {
    entries: BTreeMap<Id, AtlasEntry>,
}

impl AtlasCatalog {
    pub fn entries(&self) -> impl ExactSizeIterator<Item = &AtlasEntry> {
        self.entries.values()
    }

    pub fn entry(&self, id: Id) -> Option<&AtlasEntry> {
        self.entries.get(&id)
    }

    pub fn names(&self, id: Id) -> Option<&[String]> {
        self.entry(id).map(|entry| entry.names.as_slice())
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
            let handle = *fact.v::<Handle<LongString>>();
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

/// Load a lossless Atlas projection.
///
/// Names and descriptions are intentionally vectors. Atlas is additive and
/// has no causal register that could justify collapsing several values to one.
pub fn load_catalog<R: BlobStoreGet>(reader: &R, facts: &TribleSet) -> Result<AtlasCatalog> {
    validate_known_payloads(reader, facts)?;

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

    let mut entries = BTreeMap::new();
    for (id, handles) in name_handles {
        let names = read_text_variants(reader, handles, "name", id)?;
        // `name_handles` makes this unreachable for a valid blob store, but
        // retain the invariant explicitly at the public model boundary.
        if names.is_empty() {
            anyhow::bail!("named Atlas entity {id:x} has no readable names");
        }
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
        entries.insert(
            id,
            AtlasEntry {
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
            },
        );
    }
    Ok(AtlasCatalog { entries })
}

/// Validate one complete Atlas value without retaining its projection.
pub fn validate_catalog<R: BlobStoreGet>(reader: &R, facts: &TribleSet) -> Result<()> {
    load_catalog(reader, facts).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_preserves_every_name_and_description_variant() {
        let id = Id::new([0x41; 16]).unwrap();
        let member = Id::new([0x42; 16]).unwrap();
        let mut fragment = Fragment::empty();
        let alpha = fragment.put::<LongString, _>("Alpha".to_owned());
        let beta = fragment.put::<LongString, _>("Beta".to_owned());
        let first = fragment.put::<LongString, _>("First description".to_owned());
        let second = fragment.put::<LongString, _>("Second description".to_owned());
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
        let reader = blobs.reader().unwrap();
        let catalog = load_catalog(&reader, fragment.facts()).unwrap();
        let entry = catalog.entry(id).unwrap();

        assert_eq!(entry.names, ["Alpha", "Beta"]);
        assert_eq!(
            entry.descriptions,
            ["First description", "Second description"]
        );
        assert_eq!(entry.members, [member]);
    }
}
