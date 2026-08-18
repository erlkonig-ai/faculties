//! Validation of the collection-native Posture policy catalog.
//!
//! The canonical policy state is intrinsic channels, terms, and exemplars plus
//! immutable complete revisions. This module is the single predicate over that
//! shape: [`validate_policy_catalog`] checks a materialized collection, and
//! [`validate_policy_catalog_union`] checks the exact additive union a
//! publication would create — reading payloads staged only in memory through
//! the fragment's own blob overlay, so nothing unvalidated ever reaches the
//! pile.
//!
//! It was written inside the Posture storage cutover, which is the only reason
//! it lived there; the transform now lives in the `faculties-migrations` crate
//! and calls into this module.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::attribute::Attribute;
use triblespace::core::blob::encodings::longstring::LongString;
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::{Inline, InlineEncoding};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::core::trible::{Fragment, TribleSet};
use triblespace::macros::entity;
use triblespace::prelude::{blobencodings, inlineencodings};

use crate::schemas::embeddings::{self, Embedding768};
use crate::schemas::posture::{
    posture, EXEMPLAR_BENIGN, EXEMPLAR_PROTECTED, KIND_CHANNEL, KIND_EXEMPLAR,
    KIND_POLICY_REVISION, KIND_TERM,
};

type TextHandle = Inline<Handle<LongString>>;

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

pub fn validate_policy_catalog_with<R>(
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

pub fn tagged_entities(facts: &TribleSet, tag: Id) -> Result<BTreeSet<Id>> {
    let mut entities = BTreeSet::new();
    for entity in facts.iter().map(|fact| *fact.e()).collect::<BTreeSet<_>>() {
        if id_values(facts, entity, &metadata::tag)?.contains(&tag) {
            entities.insert(entity);
        }
    }
    Ok(entities)
}

pub fn require_tags(facts: &TribleSet, entity: Id, expected: BTreeSet<Id>, kind: &str) -> Result<()> {
    let actual = id_values(facts, entity, &metadata::tag)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual != expected {
        bail!("Posture {kind} {entity:X} has invalid tags");
    }
    Ok(())
}

pub fn entity_attributes(facts: &TribleSet, entity: Id) -> BTreeSet<Id> {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity)
        .map(|fact| *fact.a())
        .collect()
}

pub fn require_attributes(
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

pub fn inline_values<V: InlineEncoding>(
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

pub fn id_values(
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

pub fn exactly_one<T>(mut values: Vec<T>, entity: Id, field: &str) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "Posture entity {entity:X} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(values.pop().expect("length checked"))
}

pub fn at_most_one<T>(mut values: Vec<T>, entity: Id, field: &str) -> Result<Option<T>> {
    if values.len() > 1 {
        bail!(
            "Posture entity {entity:X} has {} values for {field}; expected at most one",
            values.len()
        );
    }
    Ok(values.pop())
}

pub fn read_text(reader: &PileReader, handle: TextHandle, field: &str) -> Result<String> {
    let value: View<str> = reader
        .get(handle)
        .with_context(|| format!("read Posture {field} {}", hex::encode_upper(handle.raw)))?;
    Ok(value.to_string())
}

pub fn read_text_with<R>(
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

pub fn validate_known_payloads_with<R>(
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

pub fn require_canonical_channel(value: &str) -> Result<()> {
    let canonical = value.trim().to_lowercase();
    if canonical.is_empty() || canonical != value {
        bail!("Posture channel name is not canonical");
    }
    Ok(())
}

/// Preserve the frozen lexical matcher's exact case-insensitive semantics
/// while rejecting whitespace changes that the old matcher did not erase.
pub fn canonicalize_legacy_term(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("legacy Posture term text is empty");
    }
    if trimmed != value {
        bail!("legacy Posture term text has surrounding whitespace");
    }
    Ok(value.to_lowercase())
}

pub fn require_canonical_term(value: &str) -> Result<()> {
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

pub fn canonicalize_legacy_exemplar(value: &str) -> Result<String> {
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

pub fn require_canonical_exemplar(value: &str) -> Result<()> {
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

