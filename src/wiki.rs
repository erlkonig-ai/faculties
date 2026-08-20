//! Collection-native Wiki values, strict revision-DAG reads, and admission.
//!
//! Native revision identity is the authored artifact
//! (author, title, content, tags, supersedes). Legacy version entities remain
//! byte-for-byte present after migration; additive supersedes edges connect
//! their existing ids. No fragment anchor, alias entity, mutable head, or
//! migration marker participates in either model.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace::core::attestation;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::prelude::*;

use crate::schemas::wiki::{
    attrs, authorship_fragment, revision_fragment, revision_fragment_from_handles, TextHandle,
    DEFAULT_SCOPE_ID, KIND_AUTHORSHIP, KIND_REVISION, KIND_VERSION_ID, TAG_SPECS,
};
use crate::legacy_hint::open_scope;

pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
pub type PublicKeyValue = Inline<inlineencodings::ED25519PublicKey>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorshipRecord {
    pub id: Id,
    pub author: Option<Id>,
    pub authored_at: Option<IntervalValue>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionRecord {
    pub id: Id,
    pub title: TextHandle,
    pub content: TextHandle,
    pub tags: BTreeSet<Id>,
    pub supersedes: BTreeSet<Id>,
    pub author: Option<Id>,
    /// True for a revision authored after the cutover, whose id is intrinsic
    /// over its own content. False for a preserved legacy version entity,
    /// whose id predates that identity rule and is kept byte-for-byte.
    pub native: bool,
    /// Every authoring-time observation retained on a legacy identity.
    ///
    /// The deterministic legacy writer intentionally reasserted an existing
    /// content-derived version id with a fresh timestamp. Consequently this is
    /// a set, not a scalar: collapsing it would discard exact historical facts.
    pub legacy_created_at: BTreeSet<IntervalValue>,
    pub authorships: Vec<AuthorshipRecord>,
}

impl RevisionRecord {
    pub const fn is_native(&self) -> bool {
        self.native
    }

    pub fn authored_at(&self) -> Option<IntervalValue> {
        if self.is_native() {
            self.authorships
                .iter()
                .filter_map(|record| record.authored_at)
                .min_by_key(|value| value.raw)
        } else {
            // Legacy latest-version selection used the greatest observation.
            // This also preserves A -> B -> A reverts when distinct legacy
            // states are projected onto one node each in the revision DAG.
            self.legacy_created_at.last().copied()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryRecord {
    pub roots: Vec<Id>,
    pub members: Vec<Id>,
    pub frontier: Vec<RevisionRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionReadModel {
    revisions: BTreeMap<Id, RevisionRecord>,
    entries: Vec<EntryRecord>,
}

impl RevisionReadModel {
    pub fn revision_records(&self) -> impl ExactSizeIterator<Item = &RevisionRecord> {
        self.revisions.values()
    }

    pub fn revision(&self, id: Id) -> Option<&RevisionRecord> {
        self.revisions.get(&id)
    }

    pub fn all_entries(&self) -> Vec<EntryRecord> {
        self.entries.clone()
    }

    pub fn list_entries(&self) -> Vec<EntryRecord> {
        self.entries
            .iter()
            .filter(|entry| {
                !entry.frontier.iter().all(|revision| {
                    revision
                        .tags
                        .contains(&crate::schemas::wiki::TAG_ARCHIVED_ID)
                })
            })
            .cloned()
            .collect()
    }

    pub fn cover_entries(&self, cover: Id) -> Vec<EntryRecord> {
        self.entries
            .iter()
            .filter(|entry| {
                entry
                    .frontier
                    .iter()
                    .any(|revision| revision.tags.contains(&cover))
            })
            .cloned()
            .collect()
    }

    pub fn entry_containing(&self, revision: Id) -> Option<&EntryRecord> {
        self.entries
            .iter()
            .find(|entry| entry.members.binary_search(&revision).is_ok())
    }

    /// Causal history, dependencies first. Timestamp and id only order
    /// concurrently-ready revisions; they never override supersedes.
    pub fn history(&self, entry: &EntryRecord) -> Vec<RevisionRecord> {
        let members: BTreeSet<Id> = entry.members.iter().copied().collect();
        let mut emitted = BTreeSet::new();
        let mut output = Vec::with_capacity(members.len());
        while emitted.len() < members.len() {
            let mut ready: Vec<&RevisionRecord> = members
                .iter()
                .filter(|id| !emitted.contains(*id))
                .filter_map(|id| self.revisions.get(id))
                .filter(|record| {
                    record
                        .supersedes
                        .iter()
                        .filter(|id| members.contains(*id))
                        .all(|id| emitted.contains(id))
                })
                .collect();
            ready.sort_by_key(|record| (record.authored_at().map(|value| value.raw), record.id));
            if ready.is_empty() {
                break;
            }
            for record in ready {
                emitted.insert(record.id);
                output.push(record.clone());
            }
        }
        output
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WikiCatalog {
    pub revisions: RevisionReadModel,
    pub tag_names: BTreeMap<Id, TextHandle>,
    pub author_keys: BTreeMap<Id, PublicKeyValue>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionDraft {
    pub title: String,
    pub content: String,
    pub tags: BTreeSet<Id>,
    pub predecessors: BTreeSet<Id>,
    pub author: Id,
    pub authored_at: IntervalValue,
}

fn ids_of_kind(space: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: &kind }])).collect()
}

fn id_values(
    space: &TribleSet,
    entity: Id,
    attribute: &Attribute<inlineencodings::GenId>,
) -> BTreeSet<Id> {
    find!(
        value: Id,
        pattern!(space, [{ entity @ attribute: ?value }])
    )
    .collect()
}

fn text_values(
    space: &TribleSet,
    entity: Id,
    attribute: &Attribute<inlineencodings::Handle<blobencodings::LongString>>,
) -> BTreeSet<TextHandle> {
    find!(
        value: TextHandle,
        pattern!(space, [{ entity @ attribute: ?value }])
    )
    .collect()
}

fn interval_values(
    space: &TribleSet,
    entity: Id,
    attribute: &Attribute<inlineencodings::NsTAIInterval>,
) -> BTreeSet<IntervalValue> {
    find!(
        value: IntervalValue,
        pattern!(space, [{ entity @ attribute: ?value }])
    )
    .collect()
}

fn exactly_one<T: Copy + Ord>(values: BTreeSet<T>, entity: Id, field: &str) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "Wiki entity {entity:x} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(*values.first().expect("cardinality checked"))
}

fn at_most_one<T: Copy + Ord>(values: BTreeSet<T>, entity: Id, field: &str) -> Result<Option<T>> {
    if values.len() > 1 {
        bail!(
            "Wiki entity {entity:x} has {} values for {field}; expected at most one",
            values.len()
        );
    }
    Ok(values.first().copied())
}

fn require_point(field: &str, value: IntervalValue) -> Result<()> {
    let (lower, upper): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode {field}: {error:?}"))?;
    if lower != upper {
        bail!("{field} must be a point interval");
    }
    Ok(())
}

fn entity_fact_index(space: &TribleSet) -> BTreeMap<Id, TribleSet> {
    let mut index = BTreeMap::new();
    for fact in space {
        index
            .entry(*fact.e())
            .or_insert_with(TribleSet::new)
            .insert(fact);
    }
    index
}

fn check_exact_entity(
    index: &BTreeMap<Id, TribleSet>,
    entity: Id,
    expected: &Fragment,
    label: &str,
) -> Result<()> {
    if index.get(&entity) != Some(expected.facts()) {
        bail!("Wiki {label} {entity:x} is not canonical");
    }
    Ok(())
}

fn successor_index(revisions: &BTreeMap<Id, RevisionRecord>) -> BTreeMap<Id, BTreeSet<Id>> {
    let mut successors: BTreeMap<Id, BTreeSet<Id>> =
        revisions.keys().map(|id| (*id, BTreeSet::new())).collect();
    for record in revisions.values() {
        for predecessor in &record.supersedes {
            if let Some(children) = successors.get_mut(predecessor) {
                children.insert(record.id);
            }
        }
    }
    successors
}

fn reaches(successors: &BTreeMap<Id, BTreeSet<Id>>, start: Id, target: Id) -> bool {
    let mut seen = BTreeSet::new();
    let mut stack = vec![start];
    while let Some(current) = stack.pop() {
        if let Some(children) = successors.get(&current) {
            for child in children {
                if *child == target {
                    return true;
                }
                if seen.insert(*child) {
                    stack.push(*child);
                }
            }
        }
    }
    false
}

fn validate_graph(revisions: &BTreeMap<Id, RevisionRecord>) -> Result<()> {
    for record in revisions.values() {
        for predecessor in &record.supersedes {
            if !revisions.contains_key(predecessor) {
                bail!(
                    "Wiki revision {:x} supersedes missing revision {predecessor:x}",
                    record.id
                );
            }
            if *predecessor == record.id {
                bail!("Wiki supersedes graph contains a cycle at {:x}", record.id);
            }
        }
    }

    let successors = successor_index(revisions);
    let mut remaining: BTreeMap<Id, usize> = revisions
        .iter()
        .map(|(&id, record)| (id, record.supersedes.len()))
        .collect();
    let mut ready: BTreeSet<Id> = remaining
        .iter()
        .filter_map(|(&id, &count)| (count == 0).then_some(id))
        .collect();
    let mut emitted = 0usize;
    while let Some(current) = ready.pop_first() {
        emitted += 1;
        for successor in &successors[&current] {
            let count = remaining
                .get_mut(successor)
                .expect("successor belongs to revision graph");
            *count -= 1;
            if *count == 0 {
                ready.insert(*successor);
            }
        }
    }
    if emitted != revisions.len() {
        let member = remaining
            .into_iter()
            .find_map(|(id, count)| (count > 0).then_some(id))
            .expect("unemitted graph has a member");
        bail!("Wiki supersedes graph contains a cycle at {member:x}");
    }

    for record in revisions.values().filter(|record| record.is_native()) {
        for ancestor in &record.supersedes {
            for descendant in &record.supersedes {
                if ancestor != descendant && reaches(&successors, *ancestor, *descendant) {
                    bail!(
                        "Wiki revision {:x} has redundant predecessors {ancestor:x} and {descendant:x}",
                        record.id
                    );
                }
            }
        }
    }
    Ok(())
}

/// Group revisions into entries by `metadata::supersedes` connectivity alone.
///
/// The legacy `attrs::fragment` anchor was an edge here until 2026-08-18, when
/// it became redundant: the additive migration synthesized the supersedes chain
/// FROM the anchor groups, so every anchor group is already a connected
/// component. Verified over the live corpus before removal — 11231 revisions
/// across 3035 anchors partition into the same 3095 entries, with identical
/// membership, with and without it. Since then the anchor is not read at all:
/// an id names a REVISION or it names nothing. The facts remain in the store —
/// it is append-only — and the additive migration still consumes them as legacy
/// input, but no read path in the wiki resolves one.
///
/// Each entry's frontier is [`latest`] over `space` — the shared query-layer
/// operation, not a local rule. Asking it per component rather than once over
/// every revision is only a scoping convenience: a supersedes edge always
/// unites its endpoints above, so no revision can be observed from outside its
/// own component and the two framings agree by construction.
fn entry_records(
    space: &TribleSet,
    revisions: &BTreeMap<Id, RevisionRecord>,
) -> Vec<EntryRecord> {
    let mut parent: BTreeMap<Id, Id> = revisions.keys().map(|id| (*id, *id)).collect();

    fn root(parent: &mut BTreeMap<Id, Id>, id: Id) -> Id {
        let mut cursor = id;
        while parent[&cursor] != cursor {
            cursor = parent[&cursor];
        }
        let result = cursor;
        let mut cursor = id;
        while parent[&cursor] != result {
            let next = parent[&cursor];
            parent.insert(cursor, result);
            cursor = next;
        }
        result
    }

    let mut unite = |left: Id, right: Id| {
        let left = root(&mut parent, left);
        let right = root(&mut parent, right);
        if left != right {
            let (smaller, larger) = (left.min(right), left.max(right));
            parent.insert(larger, smaller);
        }
    };
    for record in revisions.values() {
        for predecessor in &record.supersedes {
            unite(record.id, *predecessor);
        }
    }

    let mut components: BTreeMap<Id, Vec<Id>> = BTreeMap::new();
    for id in revisions.keys().copied() {
        components
            .entry(root(&mut parent, id))
            .or_default()
            .push(id);
    }
    let mut entries = Vec::new();
    for mut members in components.into_values() {
        members.sort_unstable();
        let member_set: BTreeSet<Id> = members.iter().copied().collect();
        let mut roots: Vec<Id> = members
            .iter()
            .copied()
            .filter(|id| {
                revisions[id]
                    .supersedes
                    .iter()
                    .all(|predecessor| !member_set.contains(predecessor))
            })
            .collect();
        roots.sort_unstable();
        let frontier_ids: Vec<Id> = latest(space, metadata::supersedes.id(), members.iter().copied())
            .into_iter()
            .collect();
        let frontier = frontier_ids
            .iter()
            .filter_map(|id| revisions.get(id).cloned())
            .collect();
        entries.push(EntryRecord {
            roots,
            members,
            frontier,
        });
    }
    entries.sort_by_key(|entry| entry.roots.first().copied());
    entries
}

/// Load both immutable native revisions and preserved legacy version entities.
pub fn load_catalog(space: &TribleSet) -> Result<WikiCatalog> {
    let fact_index = entity_fact_index(space);
    let native = ids_of_kind(space, KIND_REVISION);
    let legacy = ids_of_kind(space, KIND_VERSION_ID);
    if let Some(id) = native.intersection(&legacy).next() {
        bail!("Wiki entity {id:x} is both a native revision and a legacy version");
    }

    let mut revisions = BTreeMap::new();
    for id in native.iter().copied().chain(legacy.iter().copied()) {
        let is_native = native.contains(&id);
        let title = exactly_one(text_values(space, id, &attrs::title), id, "wiki::title")?;
        let content = exactly_one(text_values(space, id, &attrs::content), id, "wiki::content")?;
        let mut tags = id_values(space, id, &metadata::tag);
        tags.remove(if is_native {
            &KIND_REVISION
        } else {
            &KIND_VERSION_ID
        });
        let supersedes = id_values(space, id, &metadata::supersedes);
        let author = if is_native {
            Some(exactly_one(
                id_values(space, id, &attrs::author),
                id,
                "wiki::author",
            )?)
        } else {
            at_most_one(id_values(space, id, &attrs::author), id, "wiki::author")?
        };
        let legacy_created_at = if is_native {
            BTreeSet::new()
        } else {
            let values = interval_values(space, id, &metadata::created_at);
            if values.is_empty() {
                bail!(
                    "Wiki entity {id:x} has 0 values for metadata::created_at; expected at least one"
                );
            }
            for value in &values {
                require_point(&format!("legacy Wiki version {id:x} created-at"), *value)?;
            }
            values
        };
        if is_native {
            let expected = revision_fragment_from_handles(
                author.expect("native author"),
                title,
                content,
                &tags.iter().copied().collect::<Vec<_>>(),
                &supersedes.iter().copied().collect::<Vec<_>>(),
            );
            let canonical = expected.root().expect("native revision root");
            if canonical != id {
                bail!("Wiki revision {id:x} is non-canonical; canonical identity is {canonical:x}");
            }
            check_exact_entity(&fact_index, id, &expected, "revision")?;
        }
        revisions.insert(
            id,
            RevisionRecord {
                id,
                title,
                content,
                tags,
                supersedes,
                author,
                native: is_native,
                legacy_created_at,
                authorships: Vec::new(),
            },
        );
    }

    let mut authorships = BTreeMap::new();
    for id in ids_of_kind(space, KIND_AUTHORSHIP) {
        let revision = exactly_one(id_values(space, id, &attrs::revision), id, "wiki::revision")?;
        if !revisions.contains_key(&revision) {
            bail!("Wiki authorship {id:x} names missing revision {revision:x}");
        }
        let author = at_most_one(id_values(space, id, &attrs::author), id, "wiki::author")?;
        let authored_at = at_most_one(
            interval_values(space, id, &metadata::created_at),
            id,
            "metadata::created_at",
        )?;
        if author.is_none() && authored_at.is_none() {
            bail!("Wiki authorship {id:x} carries neither author nor created-at");
        }
        if let Some(value) = authored_at {
            require_point(&format!("Wiki authorship {id:x} created-at"), value)?;
        }
        let expected =
            authorship_fragment(revision, author, authored_at).expect("non-empty authorship");
        let canonical = expected.root().expect("authorship root");
        if canonical != id {
            bail!("Wiki authorship {id:x} is non-canonical; canonical identity is {canonical:x}");
        }
        check_exact_entity(&fact_index, id, &expected, "authorship")?;
        authorships.insert(
            id,
            (
                revision,
                AuthorshipRecord {
                    id,
                    author,
                    authored_at,
                },
            ),
        );
    }
    for (_, (revision, authorship)) in authorships {
        revisions
            .get_mut(&revision)
            .expect("authorship target checked")
            .authorships
            .push(authorship);
    }
    for revision in revisions.values_mut() {
        revision.authorships.sort_by_key(|record| record.id);
    }

    validate_graph(&revisions)?;

    let mut author_keys: BTreeMap<Id, PublicKeyValue> = BTreeMap::new();
    for (author, key) in find!(
        (author: Id, key: PublicKeyValue),
        pattern!(space, [{ ?author @ attestation::signed_by: ?key }])
    ) {
        let canonical = entity! { attestation::signed_by: key }
            .root()
            .expect("author description root");
        if canonical == author {
            if let Some(previous) = author_keys.insert(author, key) {
                if previous != key {
                    bail!("Wiki author {author:x} has conflicting public keys");
                }
            }
        }
    }
    let mut checked_authors = BTreeSet::new();
    for revision in revisions.values().filter(|record| record.is_native()) {
        let author = revision.author.expect("native author");
        let key = author_keys.get(&author).ok_or_else(|| {
            anyhow!(
                "Wiki revision {:x} has no cryptographic author description",
                revision.id
            )
        })?;
        if checked_authors.insert(author) {
            let expected = entity! { attestation::signed_by: *key };
            check_exact_entity(&fact_index, author, &expected, "author")?;
        }
        if !revision
            .authorships
            .iter()
            .any(|record| record.author == Some(author))
        {
            bail!(
                "Wiki revision {:x} has no matching queryable authorship",
                revision.id
            );
        }
        if revision
            .authorships
            .iter()
            .any(|record| record.author.is_some_and(|observed| observed != author))
        {
            bail!(
                "Wiki revision {:x} has authorship conflicting with its identity author",
                revision.id
            );
        }
    }

    let mut tag_names = BTreeMap::new();
    for (tag, name) in find!(
        (tag: Id, name: TextHandle),
        pattern!(space, [{ ?tag @ metadata::name: ?name }])
    ) {
        if let Some(previous) = tag_names.insert(tag, name) {
            if previous != name {
                bail!("Wiki tag {tag:x} has conflicting names");
            }
        }
    }
    for revision in revisions.values() {
        for tag in &revision.tags {
            if !tag_names.contains_key(tag) && !TAG_SPECS.iter().any(|(id, _)| id == tag) {
                bail!("Wiki revision {:x} uses unnamed tag {tag:x}", revision.id);
            }
        }
    }

    let entries = entry_records(space, &revisions);
    Ok(WikiCatalog {
        revisions: RevisionReadModel { revisions, entries },
        tag_names,
        author_keys,
    })
}

fn read_text_overlay<Overlay>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    handle: TextHandle,
) -> Result<String>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    if let Some(overlay) = overlay {
        if overlay.metadata(handle)?.is_some() {
            let value: View<str> = overlay.get(handle)?;
            return Ok(value.to_string());
        }
    }
    let value: View<str> = reader.get(handle)?;
    Ok(value.to_string())
}

fn validate_payloads<Overlay>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    catalog: &WikiCatalog,
) -> Result<()>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    for revision in catalog.revisions.revision_records() {
        let title = read_text_overlay(reader, overlay, revision.title)
            .with_context(|| format!("read Wiki revision {:x} title", revision.id))?;
        if title.trim().is_empty() {
            bail!("Wiki revision {:x} has an empty title", revision.id);
        }
        read_text_overlay(reader, overlay, revision.content)
            .with_context(|| format!("read Wiki revision {:x} content", revision.id))?;
    }
    for (&tag, &handle) in &catalog.tag_names {
        let name = read_text_overlay(reader, overlay, handle)
            .with_context(|| format!("read Wiki tag {tag:x} name"))?;
        if name.trim().is_empty() {
            bail!("Wiki tag {tag:x} has an empty name");
        }
        if name != name.trim().to_lowercase() {
            bail!("Wiki tag {tag:x} name is not normalized");
        }
        if let Some((_, expected)) = TAG_SPECS.iter().find(|(known, _)| known == &tag) {
            if name != *expected {
                bail!("Wiki built-in tag {tag:x} must be named {expected:?}");
            }
        }
    }
    Ok(())
}

pub fn validate_known_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts {
        if fact.a() == &attrs::title.id()
            || fact.a() == &attrs::content.id()
            || fact.a() == &metadata::name.id()
        {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::LongString>>();
            let _: View<str> = reader.get(handle).with_context(|| {
                format!("read Wiki text payload {}", hex::encode_upper(handle.raw))
            })?;
        }
    }
    Ok(())
}

pub fn validate_catalog(reader: &PileReader, facts: &TribleSet) -> Result<WikiCatalog> {
    let catalog = load_catalog(facts)?;
    validate_payloads(reader, None::<&PileReader>, &catalog)?;
    Ok(catalog)
}

/// Validate the exact additive state a native publication would create.
///
/// Newly introduced revision identities and authorship observations must name
/// the current collection signer as author. Existing facts are never rewritten
/// or removed.
pub fn validate_candidate(
    reader: &PileReader,
    current: &TribleSet,
    fragment: &Fragment,
    expected_author: Id,
) -> Result<WikiCatalog> {
    let before = ids_of_kind(current, KIND_REVISION);
    let before_authorships = ids_of_kind(current, KIND_AUTHORSHIP);
    let mut union = current.clone();
    union += fragment.facts().clone();
    let catalog = load_catalog(&union)?;
    let fact_index = entity_fact_index(&union);
    let native_ids = ids_of_kind(&union, KIND_REVISION);
    let authorship_ids = ids_of_kind(&union, KIND_AUTHORSHIP);
    let existing_entities: BTreeSet<Id> = current.iter().map(|fact| *fact.e()).collect();
    for fact in fragment.facts() {
        let entity = *fact.e();
        if native_ids.contains(&entity) || authorship_ids.contains(&entity) {
            // load_catalog already checked the complete entity against its
            // intrinsic constructor, including every fact added here.
            continue;
        }
        if let Some(key) = catalog.author_keys.get(&entity) {
            if fact.a() != &attestation::signed_by.id() {
                bail!("Wiki publication adds a non-author fact to author {entity:x}");
            }
            let expected = entity! { attestation::signed_by: *key };
            check_exact_entity(&fact_index, entity, &expected, "author")?;
            continue;
        }
        if let Some(handle) = catalog.tag_names.get(&entity) {
            if fact.a() != &metadata::name.id() {
                bail!("Wiki publication adds a non-vocabulary fact to tag {entity:x}");
            }
            if !existing_entities.contains(&entity) {
                let expected = if TAG_SPECS.iter().any(|(known, _)| *known == entity) {
                    entity! { ExclusiveId::force_ref(&entity) @ metadata::name: *handle }
                } else {
                    entity! { metadata::name: *handle }
                };
                let canonical = expected.root().expect("tag vocabulary root");
                if canonical != entity {
                    bail!(
                        "Wiki tag {entity:x} is non-canonical; canonical identity is {canonical:x}"
                    );
                }
                check_exact_entity(&fact_index, entity, &expected, "tag vocabulary")?;
            }
            continue;
        }
        bail!("Wiki publication contains an unrecognized fact on entity {entity:x}");
    }
    for revision in catalog.revisions.revision_records() {
        if revision.is_native()
            && !before.contains(&revision.id)
            && revision.author != Some(expected_author)
        {
            bail!(
                "Wiki revision {:x} author is not the publishing signer",
                revision.id
            );
        }
        for authorship in &revision.authorships {
            if !before_authorships.contains(&authorship.id)
                && authorship.author != Some(expected_author)
            {
                bail!(
                    "Wiki authorship {:x} author is not the publishing signer",
                    authorship.id
                );
            }
        }
    }
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .reader()
        .context("snapshot staged Wiki attachments")?;
    validate_payloads(reader, Some(&overlay), &catalog)?;
    Ok(catalog)
}

pub fn author_record(key: &VerifyingKey) -> (Fragment, Id) {
    let key: PublicKeyValue = (*key).to_inline();
    let fragment = entity! { attestation::signed_by: key };
    let author = fragment.root().expect("author description root");
    (fragment, author)
}

pub fn revision_record(draft: RevisionDraft) -> Result<(Fragment, Id)> {
    if draft.title.trim().is_empty() {
        bail!("Wiki title must not be empty");
    }
    for reserved in [KIND_VERSION_ID, KIND_REVISION, KIND_AUTHORSHIP] {
        if draft.tags.contains(&reserved) {
            bail!("Wiki user tags cannot use reserved record kind {reserved:x}");
        }
    }
    require_point("Wiki authored-at", draft.authored_at)?;
    let fragment = revision_fragment(
        draft.author,
        &draft.title,
        &draft.content,
        &draft.tags.into_iter().collect::<Vec<_>>(),
        &draft.predecessors.into_iter().collect::<Vec<_>>(),
    );
    let revision = fragment.root().expect("revision has one intrinsic root");
    let mut output = fragment;
    output += authorship_fragment(revision, Some(draft.author), Some(draft.authored_at))
        .expect("native authorship is non-empty");
    Ok((output, revision))
}

pub fn tag_record(name: &str) -> Result<(Fragment, Id, String)> {
    let normalized = name.trim().to_lowercase();
    if normalized.is_empty() {
        bail!("Wiki tag name must not be empty");
    }
    let mut fragment = Fragment::empty();
    let handle = fragment.put::<blobencodings::LongString, _>(normalized.clone());
    if let Some((id, _)) = TAG_SPECS.iter().find(|(_, label)| *label == normalized) {
        fragment += entity! { ExclusiveId::force_ref(id) @ metadata::name: handle };
        Ok((fragment, *id, normalized))
    } else {
        fragment += entity! { metadata::name: handle };
        let id = fragment.root().expect("intrinsic tag root");
        Ok((fragment, id, normalized))
    }
}

pub fn read_text(reader: &PileReader, handle: TextHandle) -> Result<String> {
    read_text_overlay(reader, None::<&PileReader>, handle)
}

/// Every cover-tagged maximal Wiki revision as `(title, content)`.
///
/// A fork is not silently arbitrated: each maximal revision that still carries
/// a tag named `cover` is returned. Concurrent untagged heads likewise do not
/// erase a tagged head. Callers therefore see the authored revision DAG's
/// actual frontier rather than a timestamp-selected legacy approximation.
pub fn cover_fragments(
    reader: &PileReader,
    catalog: &WikiCatalog,
) -> Result<Vec<(String, String)>> {
    let mut cover_tags = BTreeSet::new();
    for (&tag, &handle) in &catalog.tag_names {
        if read_text(reader, handle)?.eq_ignore_ascii_case("cover") {
            cover_tags.insert(tag);
        }
    }
    if cover_tags.is_empty() {
        return Ok(Vec::new());
    }

    let mut rows = Vec::new();
    for entry in catalog.revisions.all_entries() {
        for revision in entry.frontier {
            if revision.tags.is_disjoint(&cover_tags) {
                continue;
            }
            rows.push((
                read_text(reader, revision.title)?,
                read_text(reader, revision.content)?,
                revision.id,
            ));
        }
    }
    rows.sort_by(|left, right| (&left.0, left.2).cmp(&(&right.0, right.2)));
    Ok(rows
        .into_iter()
        .map(|(title, content, _)| (title, content))
        .collect())
}

pub fn materialize_collection(
    pile: &mut Pile,
    signer: &SigningKey,
) -> Result<(TribleSet, PileReader)> {
    let facts = open_scope(&mut *pile, DEFAULT_SCOPE_ID, signer.clone())
        .materialize()
        .map_err(|error| anyhow!("materialize Wiki collection: {error}"))?;
    let reader = pile
        .reader()
        .map_err(|error| anyhow!("open Wiki attachment reader: {error}"))?;
    validate_catalog(&reader, &facts)?;
    Ok((facts, reader))
}

pub fn commit_collection(
    pile: &mut Pile,
    signer: &SigningKey,
    fragment: Fragment,
) -> Result<CollectionCommit> {
    open_scope(pile, DEFAULT_SCOPE_ID, signer.clone())
        .commit(fragment)
        .map_err(|error| anyhow!("commit Wiki collection fragment: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    use hifitime::Epoch;

    fn at(seconds: f64) -> IntervalValue {
        let epoch = Epoch::from_tai_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn span(lower: f64, upper: f64) -> IntervalValue {
        (
            Epoch::from_tai_seconds(lower),
            Epoch::from_tai_seconds(upper),
        )
            .try_to_inline()
            .unwrap()
    }

    fn draft(author: Id, title: &str, predecessors: impl IntoIterator<Item = Id>) -> RevisionDraft {
        RevisionDraft {
            title: title.to_owned(),
            content: format!("{title} body"),
            tags: BTreeSet::new(),
            predecessors: predecessors.into_iter().collect(),
            author,
            authored_at: at(1.0),
        }
    }

    #[test]
    fn native_identity_includes_author_and_supports_merge() {
        let signer = SigningKey::from_bytes(&[7; 32]);
        let (author_fragment, author) = author_record(&signer.verifying_key());
        let (left_fragment, left) = revision_record(draft(author, "left", [])).unwrap();
        let (right_fragment, right) = revision_record(draft(author, "right", [])).unwrap();
        let (join_fragment, join) =
            revision_record(draft(author, "joined", [left, right])).unwrap();
        let mut facts = TribleSet::new();
        facts += author_fragment;
        facts += left_fragment;
        facts += right_fragment;
        facts += join_fragment;

        let catalog = load_catalog(&facts).unwrap();
        let entries = catalog.revisions.all_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].frontier[0].id, join);
        assert!(find!(
            authored_at: IntervalValue,
            pattern!(&facts, [{
                _?authorship @
                metadata::tag: &KIND_AUTHORSHIP,
                attrs::revision: &join,
                attrs::author: &author,
                metadata::created_at: ?authored_at,
            }])
        )
        .next()
        .is_some());

        let other = SigningKey::from_bytes(&[8; 32]);
        let (_, other_author) = author_record(&other.verifying_key());
        assert_ne!(
            revision_fragment(author, "same", "body", &[], &[]).root(),
            revision_fragment(other_author, "same", "body", &[], &[]).root()
        );
    }

    #[test]
    fn fork_remains_visible_and_history_is_causal() {
        let signer = SigningKey::from_bytes(&[9; 32]);
        let (author_fragment, author) = author_record(&signer.verifying_key());
        let (root_fragment, root) = revision_record(draft(author, "root", [])).unwrap();
        let (left_fragment, left) = revision_record(draft(author, "left", [root])).unwrap();
        let (right_fragment, right) = revision_record(draft(author, "right", [root])).unwrap();
        let mut facts = TribleSet::new();
        facts += author_fragment;
        facts += right_fragment;
        facts += root_fragment;
        facts += left_fragment;
        let model = load_catalog(&facts).unwrap().revisions;
        let entry = &model.all_entries()[0];
        let frontier: BTreeSet<Id> = entry.frontier.iter().map(|record| record.id).collect();
        assert_eq!(frontier, BTreeSet::from([left, right]));
        let history = model.history(entry);
        assert_eq!(history.first().map(|record| record.id), Some(root));
        assert_eq!(history.len(), 3);
    }

    #[test]
    fn cover_projection_keeps_each_tagged_frontier_head() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wiki.pile");
        File::create(&path).unwrap();
        let signer = SigningKey::from_bytes(&[15; 32]);
        let (author_fragment, author) = author_record(&signer.verifying_key());
        let (cover_fragment, cover, _) = tag_record("cover").unwrap();
        let (root_fragment, root) = revision_record(draft(author, "root", [])).unwrap();

        let mut left = draft(author, "left", [root]);
        left.tags.insert(cover);
        let (left_fragment, _) = revision_record(left).unwrap();
        let mut right = draft(author, "right", [root]);
        right.tags.insert(cover);
        let (right_fragment, _) = revision_record(right).unwrap();
        let (untagged_fragment, _) = revision_record(draft(author, "untagged", [root])).unwrap();

        let mut fragment = author_fragment + cover_fragment;
        fragment += root_fragment;
        fragment += left_fragment;
        fragment += right_fragment;
        fragment += untagged_fragment;

        let mut pile = crate::storage::open_pile_strict(&path).unwrap();
        crate::collection_names::open(&mut pile, DEFAULT_SCOPE_ID, signer.clone())
            .commit(fragment)
            .unwrap();
        let (facts, reader) = materialize_collection(&mut pile, &signer).unwrap();
        let catalog = validate_catalog(&reader, &facts).unwrap();
        assert_eq!(
            cover_fragments(&reader, &catalog).unwrap(),
            vec![
                ("left".to_owned(), "left body".to_owned()),
                ("right".to_owned(), "right body".to_owned()),
            ]
        );
        pile.close().unwrap();
    }

    #[test]
    fn native_authorship_cannot_claim_a_different_author() {
        let signer = SigningKey::from_bytes(&[10; 32]);
        let (author_fragment, author) = author_record(&signer.verifying_key());
        let (revision_fragment, revision) = revision_record(draft(author, "authored", [])).unwrap();
        let impostor = genid().id;
        let conflicting = authorship_fragment(revision, Some(impostor), Some(at(2.0))).unwrap();
        let mut facts = TribleSet::new();
        facts += author_fragment;
        facts += revision_fragment;
        facts += conflicting;
        assert!(load_catalog(&facts)
            .unwrap_err()
            .to_string()
            .contains("conflicting with its identity author"));
    }

    #[test]
    fn native_authorship_is_bound_to_its_publishing_signer() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wiki.pile");
        File::create(&path).unwrap();
        let mut pile = crate::storage::open_pile_strict(&path).unwrap();
        let reader = pile.reader().unwrap();
        pile.close().unwrap();

        let owner = SigningKey::from_bytes(&[13; 32]);
        let (author_fragment, author) = author_record(&owner.verifying_key());
        let (revision_fragment, revision) = revision_record(draft(author, "owned", [])).unwrap();
        let mut current = author_fragment.facts().clone();
        current += revision_fragment.facts().clone();

        let impostor = SigningKey::from_bytes(&[14; 32]);
        let (_, impostor_author) = author_record(&impostor.verifying_key());
        let claimed = authorship_fragment(revision, Some(author), Some(at(2.0))).unwrap();
        assert!(
            validate_candidate(&reader, &current, &claimed, impostor_author)
                .unwrap_err()
                .to_string()
                .contains("author is not the publishing signer")
        );
    }

    #[test]
    fn native_admission_rejects_unrecognized_facts_and_unnormalized_tags() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wiki.pile");
        File::create(&path).unwrap();
        let mut pile = crate::storage::open_pile_strict(&path).unwrap();
        let reader = pile.reader().unwrap();
        pile.close().unwrap();

        let signer = SigningKey::from_bytes(&[11; 32]);
        let (author_fragment, author) = author_record(&signer.verifying_key());
        let (revision_fragment, _) = revision_record(draft(author, "strict", [])).unwrap();
        let mut unexpected = author_fragment + revision_fragment;
        unexpected += entity! { metadata::description: "not Wiki state" };
        assert!(
            validate_candidate(&reader, &TribleSet::new(), &unexpected, author)
                .unwrap_err()
                .to_string()
                .contains("unrecognized fact")
        );

        let mut bad_tag = Fragment::empty();
        let handle = bad_tag.put::<blobencodings::LongString, _>(" Mixed ".to_owned());
        bad_tag += entity! { metadata::name: handle };
        let tag = bad_tag.root().unwrap();
        let mut tagged = draft(author, "tagged", []);
        tagged.tags.insert(tag);
        let (revision, _) = revision_record(tagged).unwrap();
        bad_tag += author_record(&signer.verifying_key()).0;
        bad_tag += revision;
        assert!(
            validate_candidate(&reader, &TribleSet::new(), &bad_tag, author)
                .unwrap_err()
                .to_string()
                .contains("not normalized")
        );
    }

    /// The legacy anchor is nothing at all now — not an edge, not a selector.
    ///
    /// Its facts are still in the store, because the store is append-only, and
    /// the fixture keeps them for exactly that reason. Two versions carrying
    /// the same anchor and NO `supersedes` between them are two entries, and
    /// the anchor id itself resolves to no revision: lineage is read from the
    /// supersedes facts the migration wrote down, and from nothing else.
    #[test]
    fn a_shared_legacy_anchor_groups_nothing_and_names_nothing() {
        let fragment = genid().id;
        let first = genid().id;
        let second = genid().id;
        let mut facts = entity! { ExclusiveId::force_ref(&first) @
            metadata::tag: &KIND_VERSION_ID,
            attrs::fragment: fragment,
            attrs::title: "T".to_blob().get_handle(),
            attrs::content: "one".to_blob().get_handle(),
            metadata::created_at: at(1.0),
        }
        .into_facts();
        facts += entity! { ExclusiveId::force_ref(&second) @
            metadata::tag: &KIND_VERSION_ID,
            attrs::fragment: fragment,
            attrs::title: "T".to_blob().get_handle(),
            attrs::content: "two".to_blob().get_handle(),
            metadata::created_at: at(2.0),
        }
        .into_facts();
        let model = load_catalog(&facts).unwrap().revisions;
        assert_eq!(model.all_entries().len(), 2);
        assert_ne!(
            model.entry_containing(first).unwrap().members,
            model.entry_containing(second).unwrap().members
        );
        assert!(
            model.revision(fragment).is_none(),
            "an anchor id must resolve to no revision"
        );
        assert!(
            model.entry_containing(fragment).is_none(),
            "an anchor id must belong to no entry"
        );
    }

    #[test]
    fn legacy_ids_and_facts_are_read_without_aliases() {
        let fragment = genid().id;
        let first = genid().id;
        let second = genid().id;
        let mut facts = entity! { ExclusiveId::force_ref(&first) @
            metadata::tag: &KIND_VERSION_ID,
            attrs::fragment: fragment,
            attrs::title: "T".to_blob().get_handle(),
            attrs::content: "one".to_blob().get_handle(),
            metadata::created_at: at(1.0),
        }
        .into_facts();
        facts += entity! { ExclusiveId::force_ref(&second) @
            metadata::tag: &KIND_VERSION_ID,
            attrs::fragment: fragment,
            attrs::title: "T".to_blob().get_handle(),
            attrs::content: "two".to_blob().get_handle(),
            metadata::created_at: at(2.0),
            metadata::supersedes: first,
        }
        .into_facts();
        let model = load_catalog(&facts).unwrap().revisions;
        // Both legacy ids keep their identity and their lineage...
        assert!(model.revision(first).is_some());
        assert_eq!(model.revision(second).unwrap().supersedes.iter().copied().collect::<Vec<_>>(), vec![first]);
        assert!(!model.revision(first).unwrap().is_native());
        let entry = model.entry_containing(second).unwrap();
        assert_eq!(entry.frontier.iter().map(|head| head.id).collect::<Vec<_>>(), vec![second]);
        // ...and the anchor they were written under names nothing.
        assert!(model.revision(fragment).is_none());
    }

    #[test]
    fn legacy_reassertions_preserve_all_times_and_project_the_latest() {
        let fragment = genid().id;
        let version = genid().id;
        let observed = [at(1.0), at(3.0)];
        let facts = entity! { ExclusiveId::force_ref(&version) @
            metadata::tag: &KIND_VERSION_ID,
            attrs::fragment: fragment,
            attrs::title: "T".to_blob().get_handle(),
            attrs::content: "same state".to_blob().get_handle(),
            metadata::created_at*: observed.iter(),
        }
        .into_facts();

        let model = load_catalog(&facts).unwrap().revisions;
        let record = model.revision(version).unwrap();
        assert_eq!(
            record.legacy_created_at,
            BTreeSet::from(observed),
            "no historical timestamp observation is discarded"
        );
        assert_eq!(
            record.authored_at(),
            Some(observed[1]),
            "legacy current-state semantics use the latest reassertion"
        );
    }

    #[test]
    fn every_legacy_timestamp_observation_must_remain_a_point() {
        let fragment = genid().id;
        let version = genid().id;
        let observed = [at(1.0), span(2.0, 3.0)];
        let facts = entity! { ExclusiveId::force_ref(&version) @
            metadata::tag: &KIND_VERSION_ID,
            attrs::fragment: fragment,
            attrs::title: "T".to_blob().get_handle(),
            attrs::content: "state".to_blob().get_handle(),
            metadata::created_at*: observed.iter(),
        }
        .into_facts();

        assert!(load_catalog(&facts)
            .unwrap_err()
            .to_string()
            .contains("must be a point interval"));
    }

    #[test]
    fn supersedes_cycles_are_rejected() {
        let fragment = genid().id;
        let first = genid().id;
        let second = genid().id;
        let mut facts = entity! { ExclusiveId::force_ref(&first) @
            metadata::tag: &KIND_VERSION_ID,
            attrs::fragment: fragment,
            attrs::title: "T".to_blob().get_handle(),
            attrs::content: "one".to_blob().get_handle(),
            metadata::created_at: at(1.0),
            metadata::supersedes: second,
        }
        .into_facts();
        facts += entity! { ExclusiveId::force_ref(&second) @
            metadata::tag: &KIND_VERSION_ID,
            attrs::fragment: fragment,
            attrs::title: "T".to_blob().get_handle(),
            attrs::content: "two".to_blob().get_handle(),
            metadata::created_at: at(2.0),
            metadata::supersedes: first,
        }
        .into_facts();

        assert!(load_catalog(&facts)
            .unwrap_err()
            .to_string()
            .contains("supersedes graph contains a cycle"));
    }

    #[test]
    fn native_revision_rejects_redundant_predecessors() {
        let signer = SigningKey::from_bytes(&[12; 32]);
        let (author_fragment, author) = author_record(&signer.verifying_key());
        let (root_fragment, root) = revision_record(draft(author, "root", [])).unwrap();
        let (child_fragment, child) = revision_record(draft(author, "child", [root])).unwrap();
        let (redundant_fragment, redundant) =
            revision_record(draft(author, "redundant", [root, child])).unwrap();
        let mut facts = TribleSet::new();
        facts += author_fragment;
        facts += root_fragment;
        facts += child_fragment;
        facts += redundant_fragment;

        let error = load_catalog(&facts).unwrap_err().to_string();
        assert!(error.contains(&format!("Wiki revision {redundant:x}")));
        assert!(error.contains("has redundant predecessors"));
    }
}
