//! Collection-native Wiki values and strict revision-DAG reads.
//!
//! Native revision identity is the authored artifact
//! (author, title, content, tags, supersedes). Legacy version entities remain
//! byte-for-byte present after migration; additive supersession facts connect
//! their existing ids. A collection COMMIT records curation: its signer chose
//! to publish the artifact, but is not thereby asserted to be its author. No
//! fragment anchor, alias entity, mutable head, or migration marker
//! participates in either model.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace::core::attestation;
use triblespace::core::collection::latest::{LatestBlob, LatestIndex};
use triblespace::core::collection::{CollectionCommit, CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::query::register::{resolve, ObservationOrder, RegisterOrder};
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::{BlobStoreGet, CapabilityProofRead, SnapshotSource};
use triblespace::prelude::*;

use crate::collection_names::open_configured;
use crate::schemas::wiki::{
    attrs, authorship_fragment, extract_link_targets, revision_fragment,
    revision_fragment_from_handles, TextHandle, DEFAULT_SCOPE_ID, KIND_AUTHORSHIP, KIND_REVISION,
    KIND_VERSION_ID, TAG_ARCHIVED_ID, TAG_SPECS,
};
use crate::storage::FactArchive;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};

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
                !entry
                    .frontier
                    .iter()
                    .all(|revision| revision.tags.contains(&TAG_ARCHIVED_ID))
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

/// One coherent, shard-preserving Wiki query snapshot and its maintained
/// positive latest-state relation.
pub struct WikiQuerySnapshot {
    facts: FactArchive,
    store_snapshot: PileSnapshot,
    latest: LatestIndex,
}

impl WikiQuerySnapshot {
    /// Shard-preserving facts admitted by this exact snapshot.
    pub fn facts(&self) -> &FactArchive {
        &self.facts
    }

    /// Blob reader captured while validating this exact snapshot.
    pub fn store_snapshot(&self) -> &PileSnapshot {
        &self.store_snapshot
    }

    /// Known latest states attached from the same immutable store observation.
    pub fn latest(&self) -> &LatestIndex {
        &self.latest
    }

    /// Consume the coherent snapshot into its query substrate and indexes.
    pub fn into_parts(self) -> (FactArchive, PileSnapshot, LatestIndex) {
        (self.facts, self.store_snapshot, self.latest)
    }
}

/// Strict detached Wiki projection retained for migrations and import
/// preflight. Ordinary readers use [`WikiQuerySnapshot`] instead.
pub struct WikiSnapshot {
    facts: TribleSet,
    store_snapshot: PileSnapshot,
    latest: LatestIndex,
    catalog: WikiCatalog,
}

impl WikiSnapshot {
    pub fn facts(&self) -> &TribleSet {
        &self.facts
    }

    pub fn store_snapshot(&self) -> &PileSnapshot {
        &self.store_snapshot
    }

    pub fn latest(&self) -> &LatestIndex {
        &self.latest
    }

    pub fn catalog(&self) -> &WikiCatalog {
        &self.catalog
    }

    pub fn into_parts(self) -> (TribleSet, PileSnapshot, LatestIndex, WikiCatalog) {
        (self.facts, self.store_snapshot, self.latest, self.catalog)
    }
}

/// Maintained positive latest-state projection used for Wiki frontiers.
pub fn latest_collection<S>(
    store: &mut S,
    authority: VerifyingKey,
) -> Result<Collection<LatestBlob>>
where
    S: CollectionStoreExt + SnapshotSource,
    <S as SnapshotSource>::Snapshot: BlobStoreGet + CapabilityProofRead,
{
    let source = crate::collection_names::open_configured(store, DEFAULT_SCOPE_ID, authority)?;
    let target = store.derive::<LatestBlob>(
        source,
        metadata::supersedes.id(),
        crate::collection_names::private_policy(authority),
    )?;
    Ok(target)
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

fn ids_of_kind<P: TriblePattern>(space: &P, kind: Id) -> BTreeSet<Id> {
    find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: &kind }])).collect()
}

fn id_values<P: TriblePattern>(
    space: &P,
    entity: Id,
    attribute: &Attribute<inlineencodings::GenId>,
) -> BTreeSet<Id> {
    find!(
        value: Id,
        pattern!(space, [{ entity @ attribute: ?value }])
    )
    .collect()
}

fn text_values<P: TriblePattern>(
    space: &P,
    entity: Id,
    attribute: &Attribute<inlineencodings::Handle<blobencodings::UTF8String>>,
) -> BTreeSet<TextHandle> {
    find!(
        value: TextHandle,
        pattern!(space, [{ entity @ attribute: ?value }])
    )
    .collect()
}

fn interval_values<P: TriblePattern>(
    space: &P,
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

/// Every queryable Wiki revision id.
///
/// This is a typed projection, not a catalog load: incomplete or undecodable
/// rows simply do not satisfy either revision pattern. Native revisions need
/// their author relation; preserved legacy versions do not.
pub fn revision_ids<P: TriblePattern>(space: &P) -> BTreeSet<Id> {
    let native = find!(
        id: Id,
        pattern!(space, [{
            ?id @ metadata::tag: &KIND_REVISION,
            attrs::title: _?title,
            attrs::content: _?content,
            attrs::author: _?author,
        }])
    );
    let legacy = find!(
        id: Id,
        pattern!(space, [{
            ?id @ metadata::tag: &KIND_VERSION_ID,
            attrs::title: _?title,
            attrs::content: _?content,
        }])
    );
    native.chain(legacy).collect()
}

fn optional_values<T: Copy + Ord>(values: BTreeSet<T>) -> Vec<Option<T>> {
    if values.is_empty() {
        vec![None]
    } else {
        values.into_iter().map(Some).collect()
    }
}

fn query_authorships<P: TriblePattern>(space: &P, revision: Id) -> Vec<AuthorshipRecord> {
    let ids: BTreeSet<Id> = find!(
        id: Id,
        pattern!(space, [{
            ?id @ metadata::tag: &KIND_AUTHORSHIP,
            attrs::revision: &revision,
        }])
    )
    .collect();
    let mut records = Vec::new();
    for id in ids {
        let authors = optional_values(id_values(space, id, &attrs::author));
        let times = optional_values(interval_values(space, id, &metadata::created_at));
        for author in &authors {
            for authored_at in &times {
                records.push(AuthorshipRecord {
                    id,
                    author: *author,
                    authored_at: *authored_at,
                });
            }
        }
    }
    records.sort_by_key(|record| (record.id, record.author, record.authored_at));
    records
}

/// Project every typed interpretation of one Wiki revision directly from a
/// query substrate.
///
/// Scalar multiplicity is kept visible as multiple projections rather than
/// rejected collection-wide or settled by iterator order. Set-valued tags,
/// predecessors, legacy timestamps, and authorship observations remain sets.
pub fn revision_records<P: TriblePattern>(space: &P, id: Id) -> Vec<RevisionRecord> {
    let title_content: BTreeSet<(TextHandle, TextHandle)> = find!(
        (title: TextHandle, content: TextHandle),
        pattern!(space, [{ id @ attrs::title: ?title, attrs::content: ?content }])
    )
    .collect();
    if title_content.is_empty() {
        return Vec::new();
    }

    let mut tags = id_values(space, id, &metadata::tag);
    tags.remove(&KIND_REVISION);
    tags.remove(&KIND_VERSION_ID);
    let supersedes = id_values(space, id, &metadata::supersedes);
    let authorships = query_authorships(space, id);
    let legacy_created_at = interval_values(space, id, &metadata::created_at);
    let authors = id_values(space, id, &attrs::author);
    let native = exists!(
        (),
        pattern!(space, [{ id @ metadata::tag: &KIND_REVISION }])
    );
    let legacy = exists!(
        (),
        pattern!(space, [{ id @ metadata::tag: &KIND_VERSION_ID }])
    );
    let mut records = Vec::new();

    if native {
        for (title, content) in &title_content {
            for author in &authors {
                records.push(RevisionRecord {
                    id,
                    title: *title,
                    content: *content,
                    tags: tags.clone(),
                    supersedes: supersedes.clone(),
                    author: Some(*author),
                    native: true,
                    legacy_created_at: BTreeSet::new(),
                    authorships: authorships.clone(),
                });
            }
        }
    }
    if legacy {
        for (title, content) in &title_content {
            for author in optional_values(authors.clone()) {
                records.push(RevisionRecord {
                    id,
                    title: *title,
                    content: *content,
                    tags: tags.clone(),
                    supersedes: supersedes.clone(),
                    author,
                    native: false,
                    legacy_created_at: legacy_created_at.clone(),
                    authorships: authorships.clone(),
                });
            }
        }
    }
    records
}

fn adjacent_revisions<P: TriblePattern>(space: &P, revision: Id) -> BTreeSet<Id> {
    let predecessors = find!(
        id: Id,
        pattern!(space, [{ revision @ metadata::supersedes: ?id }])
    );
    let successors = find!(
        id: Id,
        pattern!(space, [{ ?id @ metadata::supersedes: &revision }])
    );
    predecessors
        .chain(successors)
        .filter(|id| !revision_records(space, *id).is_empty())
        .collect()
}

/// The connected revision entry containing `seed`, projected at the point of
/// use. Only the supersession relation is traversed; no whole-Wiki catalog is
/// constructed.
pub fn entry<P: TriblePattern>(space: &P, latest: &LatestIndex, seed: Id) -> Option<EntryRecord> {
    if revision_records(space, seed).is_empty() {
        return None;
    }
    let mut members = BTreeSet::from([seed]);
    let mut pending = vec![seed];
    while let Some(current) = pending.pop() {
        for adjacent in adjacent_revisions(space, current) {
            if members.insert(adjacent) {
                pending.push(adjacent);
            }
        }
    }
    let roots = members
        .iter()
        .copied()
        .filter(|id| id_values(space, *id, &metadata::supersedes).is_disjoint(&members))
        .collect();
    let members: Vec<Id> = members.into_iter().collect();
    let frontier =
        find!(id: Id, and!(latest.has(id), SortedSlice::new_unchecked(&members).has(id)))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .flat_map(|id| revision_records(space, id))
            .collect();
    Some(EntryRecord {
        roots,
        members,
        frontier,
    })
}

/// Every connected Wiki entry, discovered from typed revision rows and
/// projected independently. This is intended only for commands whose answer
/// genuinely ranges over the whole Wiki (list, search, audits, export).
pub fn entries<P: TriblePattern>(space: &P, latest: &LatestIndex) -> Vec<EntryRecord> {
    let mut remaining = revision_ids(space);
    let mut entries = Vec::new();
    while let Some(seed) = remaining.pop_first() {
        if let Some(entry) = entry(space, latest, seed) {
            for member in &entry.members {
                remaining.remove(member);
            }
            entries.push(entry);
        }
    }
    entries.sort_by_key(|entry| entry.roots.first().copied());
    entries
}

/// Causal history for one already-scoped entry, dependencies first.
pub fn entry_history<P: TriblePattern>(space: &P, entry: &EntryRecord) -> Vec<RevisionRecord> {
    let members: BTreeSet<Id> = entry.members.iter().copied().collect();
    let mut emitted = BTreeSet::new();
    let mut output = Vec::new();
    while emitted.len() < members.len() {
        let mut ready: Vec<Id> = members
            .iter()
            .copied()
            .filter(|id| !emitted.contains(id))
            .filter(|id| {
                id_values(space, *id, &metadata::supersedes)
                    .intersection(&members)
                    .all(|predecessor| emitted.contains(predecessor))
            })
            .collect();
        ready.sort_by_key(|id| {
            let authored_at = revision_records(space, *id)
                .into_iter()
                .filter_map(|record| record.authored_at().map(|value| value.raw))
                .min();
            (authored_at, *id)
        });
        if ready.is_empty() {
            break;
        }
        for id in ready {
            emitted.insert(id);
            output.extend(revision_records(space, id));
        }
    }
    output
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
/// Each entry's frontier is [`resolve`] over `order` — the shared query-layer
/// operation, not a local rule. Asking it per component rather than once over
/// every revision is only a scoping convenience: a supersedes edge always
/// unites its endpoints above, so no revision can be observed from outside its
/// own component and the two framings agree by construction.
fn entry_records<O>(order: &O, revisions: &BTreeMap<Id, RevisionRecord>) -> Vec<EntryRecord>
where
    O: RegisterOrder + ?Sized,
{
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
        let frontier_ids: Vec<Id> = resolve(order, members.iter().copied())
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

/// Load both immutable native revisions and preserved legacy version entities
/// using a caller-supplied supersession order.
pub fn load_catalog_with_order<O>(space: &TribleSet, order: &O) -> Result<WikiCatalog>
where
    O: RegisterOrder + ?Sized,
{
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

    for fact in space
        .iter()
        .filter(|fact| fact.a() == &metadata::supersedes.id())
    {
        let successor = *fact.e();
        let predecessor: Id = fact
            .v::<inlineencodings::GenId>()
            .try_from_inline()
            .map_err(|error| {
                anyhow!("Wiki supersedes target on {successor:x} is not an id: {error:?}")
            })?;
        if !revisions.contains_key(&successor) {
            bail!("Wiki supersedes source {successor:x} is not a known Wiki revision");
        }
        if !revisions.contains_key(&predecessor) {
            bail!("Wiki supersedes target {predecessor:x} is not a known Wiki revision");
        }
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

    let entries = entry_records(order, &revisions);
    Ok(WikiCatalog {
        revisions: RevisionReadModel { revisions, entries },
        tag_names,
        author_keys,
    })
}

/// Reference implementation that derives the supersession order directly.
///
/// Migrations, detached fact-set validation, and tests use this as an oracle.
/// Durable application reads use [`materialize_indexed_collection`] so the
/// exact collection cover and its maintained order stay attached.
pub fn load_catalog(space: &TribleSet) -> Result<WikiCatalog> {
    let order = ObservationOrder::new(space, metadata::supersedes.id());
    load_catalog_with_order(space, &order)
}

fn validate_payloads(reader: &PileSnapshot, catalog: &WikiCatalog) -> Result<()> {
    for revision in catalog.revisions.revision_records() {
        let title = read_text(reader, revision.title)
            .with_context(|| format!("read Wiki revision {:x} title", revision.id))?;
        if title.trim().is_empty() {
            bail!("Wiki revision {:x} has an empty title", revision.id);
        }
        read_text(reader, revision.content)
            .with_context(|| format!("read Wiki revision {:x} content", revision.id))?;
    }
    for (&tag, &handle) in &catalog.tag_names {
        let name =
            read_text(reader, handle).with_context(|| format!("read Wiki tag {tag:x} name"))?;
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

pub fn validate_known_payloads(reader: &PileSnapshot, facts: &TribleSet) -> Result<()> {
    for fact in facts {
        if fact.a() == &attrs::title.id()
            || fact.a() == &attrs::content.id()
            || fact.a() == &metadata::name.id()
        {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::UTF8String>>();
            let _: View<str> = reader.get(handle).with_context(|| {
                format!("read Wiki text payload {}", hex::encode_upper(handle.raw))
            })?;
        }
    }
    Ok(())
}

/// Strictly validate a detached Wiki snapshot with the reference resolver.
///
/// This is the migration/import and test-oracle boundary. Durable application
/// reads should use [`materialize_indexed_collection`].
pub fn validate_catalog(reader: &PileSnapshot, facts: &TribleSet) -> Result<WikiCatalog> {
    let catalog = load_catalog(facts)?;
    validate_payloads(reader, &catalog)?;
    Ok(catalog)
}

/// Validate one Wiki fact snapshot using an already attached supersession
/// order for exactly that snapshot's source cover.
pub fn validate_catalog_with_order<O>(
    reader: &PileSnapshot,
    facts: &TribleSet,
    order: &O,
) -> Result<WikiCatalog>
where
    O: RegisterOrder + ?Sized,
{
    let catalog = load_catalog_with_order(facts, order)?;
    validate_payloads(reader, &catalog)?;
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
    let handle = fragment.put::<blobencodings::UTF8String, _>(normalized.clone());
    if let Some((id, _)) = TAG_SPECS.iter().find(|(_, label)| *label == normalized) {
        fragment += entity! { ExclusiveId::force_ref(id) @ metadata::name: handle };
        Ok((fragment, *id, normalized))
    } else {
        fragment += entity! { metadata::name: handle };
        let id = fragment.root().expect("intrinsic tag root");
        Ok((fragment, id, normalized))
    }
}

pub fn read_text(reader: &PileSnapshot, handle: TextHandle) -> Result<String> {
    let value: View<str> = reader.get(handle)?;
    Ok(value.to_string())
}

/// Every cover-tagged maximal Wiki revision as `(title, content)`.
///
/// A fork is not silently arbitrated: each maximal revision that still carries
/// a tag named `cover` is returned. Concurrent untagged heads likewise do not
/// erase a tagged head. Callers therefore see the authored revision DAG's
/// actual frontier rather than a timestamp-selected legacy approximation.
pub fn cover_fragments<P: TriblePattern>(
    reader: &PileSnapshot,
    facts: &P,
    latest: &LatestIndex,
) -> Result<Vec<(String, String)>> {
    let frontier: Vec<RevisionRecord> = find!(revision: Id, latest.has(revision))
        .flat_map(|revision| revision_records(facts, revision))
        .collect();
    let candidate_tags: BTreeSet<Id> = frontier
        .iter()
        .flat_map(|revision| revision.tags.iter().copied())
        .collect();
    let mut cover_tags = BTreeSet::new();
    for tag in candidate_tags {
        for handle in find!(
            handle: TextHandle,
            pattern!(facts, [{ tag @ metadata::name: ?handle }])
        ) {
            if read_text(reader, handle)?.eq_ignore_ascii_case("cover") {
                cover_tags.insert(tag);
            }
        }
    }
    if cover_tags.is_empty() {
        return Ok(Vec::new());
    }

    let mut rows = Vec::new();
    for revision in frontier {
        if revision.tags.is_disjoint(&cover_tags) {
            continue;
        }
        rows.push((
            read_text(reader, revision.title)?,
            read_text(reader, revision.content)?,
            revision.id,
        ));
    }
    rows.sort_by(|left, right| (&left.0, left.2).cmp(&(&right.0, right.2)));
    rows.dedup();
    Ok(rows
        .into_iter()
        .map(|(title, content, _)| (title, content))
        .collect())
}

// ── the frontier link model ────────────────────────────────────────────────
//
// Reproduced from admitted content: [`extract_link_targets`] is the one
// extractor, and a target id names the ENTRY that contains the revision it
// points at. Forks stay forks — an entry with two current states is evidence,
// not a row to settle by clock or iteration order — so every read below is
// per-state and the entry keeps all of them.
//
// Lifted out of the `gauge` binary on 2026-08-27 so the link audit in the
// `wiki` CLI and gauge's metrics share one model instead of growing a second
// extractor that drifts from the first.

/// Display name for a tag id, falling back to the built-in vocabulary and
/// then to hex, so an unnamed tag still prints something addressable.
pub fn tag_display_name(catalog: &WikiCatalog, reader: &PileSnapshot, id: Id) -> Result<String> {
    match catalog.tag_names.get(&id) {
        Some(handle) => read_text(reader, *handle),
        None => Ok(TAG_SPECS
            .iter()
            .find_map(|(known, label)| (*known == id).then_some((*label).to_owned()))
            .unwrap_or_else(|| format!("{id:x}"))),
    }
}

/// Display every name asserted for a tag directly from a query substrate.
/// Multiplicity stays visible instead of becoming a collection-wide error or
/// an iteration-order winner.
pub fn tag_display_name_from_facts<P: TriblePattern>(
    facts: &P,
    reader: &PileSnapshot,
    id: Id,
) -> Result<String> {
    let mut names = BTreeSet::new();
    for handle in find!(
        handle: TextHandle,
        pattern!(facts, [{ id @ metadata::name: ?handle }])
    ) {
        names.insert(read_text(reader, handle)?);
    }
    Ok(if names.is_empty() {
        TAG_SPECS
            .iter()
            .find_map(|(known, label)| (*known == id).then_some((*label).to_owned()))
            .unwrap_or_else(|| format!("{id:x}"))
    } else {
        names.into_iter().collect::<Vec<_>>().join(" / ")
    })
}

/// One current state of an entry, with its content-derived link targets.
#[derive(Clone, Debug)]
pub struct FrontierState {
    pub revision: Id,
    pub title: String,
    pub tags: BTreeSet<String>,
    pub links: Vec<Id>,
}

/// One logical entry: a stable label, every current state, and whether any of
/// those states is still un-archived.
#[derive(Clone, Debug)]
pub struct FrontierEntry {
    pub label: Id,
    pub states: Vec<FrontierState>,
    pub active: bool,
}

impl FrontierEntry {
    /// The agreed title, or every forked title, on one line.
    pub fn title(&self) -> String {
        let titles: BTreeSet<&str> = self
            .states
            .iter()
            .map(|state| state.title.as_str())
            .collect();
        if titles.len() == 1 {
            titles.first().expect("one title").to_string()
        } else {
            format!(
                "FORK: {}",
                titles.into_iter().collect::<Vec<_>>().join(" | ")
            )
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkResolution {
    Missing,
    Unique(usize),
    Ambiguous(Vec<usize>),
}

/// Every entry's current states, plus the indexes that make a link target
/// resolvable: revision ids directly, legacy fragment anchors through the
/// compatibility path, and the non-revision entities a target might name.
#[derive(Clone, Debug)]
pub struct FrontierModel {
    pub entries: Vec<FrontierEntry>,
    selectors: BTreeMap<Id, BTreeSet<usize>>,
    anchors: BTreeMap<Id, BTreeSet<usize>>,
    kinds: BTreeMap<Id, OtherKind>,
}

impl FrontierModel {
    pub fn load<P: TriblePattern>(
        reader: &PileSnapshot,
        facts: &P,
        latest: &LatestIndex,
    ) -> Result<Self> {
        let records = entries(facts, latest);
        let mut entries = Vec::with_capacity(records.len());
        let mut selectors: BTreeMap<Id, BTreeSet<usize>> = BTreeMap::new();

        for (index, entry) in records.iter().enumerate() {
            let label = *entry.roots.first().expect("admitted Wiki entry has a root");
            let mut states = Vec::with_capacity(entry.frontier.len());
            for revision in &entry.frontier {
                let title = read_text(reader, revision.title)?;
                let content = read_text(reader, revision.content)?;
                let tags = revision
                    .tags
                    .iter()
                    .map(|tag| tag_display_name_from_facts(facts, reader, *tag))
                    .collect::<Result<BTreeSet<_>>>()?;
                let links = extract_link_targets(&content)
                    .into_iter()
                    .filter_map(|raw| Id::from_hex(&raw))
                    .collect();
                states.push(FrontierState {
                    revision: revision.id,
                    title,
                    tags,
                    links,
                });
            }
            for revision in &entry.members {
                selectors.entry(*revision).or_default().insert(index);
            }
            let active = entry
                .frontier
                .iter()
                .any(|revision| !revision.tags.contains(&TAG_ARCHIVED_ID));
            entries.push(FrontierEntry {
                label,
                states,
                active,
            });
        }

        let anchors = Self::index_anchors(facts, &selectors);
        let mut kinds = BTreeMap::new();
        for (id, _) in TAG_SPECS {
            kinds.insert(id, OtherKind::Tag);
        }
        for id in find!(
            id: Id,
            pattern!(facts, [{ ?id @ metadata::name: _?name }])
        ) {
            kinds.insert(id, OtherKind::Tag);
        }
        for id in find!(
            id: Id,
            pattern!(facts, [{ ?id @ attestation::signed_by: _?key }])
        ) {
            kinds.insert(id, OtherKind::Author);
        }
        for id in revision_ids(facts) {
            for record in revision_records(facts, id) {
                for authorship in &record.authorships {
                    kinds.insert(authorship.id, OtherKind::Authorship);
                }
            }
        }

        Ok(Self {
            entries,
            selectors,
            anchors,
            kinds,
        })
    }

    pub fn resolve(&self, target: Id) -> LinkResolution {
        match self.selectors.get(&target) {
            None => LinkResolution::Missing,
            Some(entries) if entries.len() == 1 => {
                LinkResolution::Unique(*entries.first().expect("one entry"))
            }
            Some(entries) => LinkResolution::Ambiguous(entries.iter().copied().collect()),
        }
    }

    pub fn state_count(&self) -> usize {
        self.active_entries().map(|entry| entry.states.len()).sum()
    }

    pub fn active_entries(&self) -> impl Iterator<Item = &FrontierEntry> {
        self.entries.iter().filter(|entry| entry.active)
    }

    pub fn active_count(&self) -> usize {
        self.active_entries().count()
    }
}

// ── what a dangling link actually means ────────────────────────────────────
//
// A wiki whose convention is to LINK LIBERALLY cannot treat every unresolved
// target as a defect: a link to a page nobody has written yet marks work, not
// breakage. Three outcomes are genuinely different and a report that merges
// them is worse than no report at all.

/// A non-revision Wiki entity a link target happens to name.
///
/// Not breakage in itself — it says the reference points at the wrong KIND of
/// thing, which is a different mistake from pointing at nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OtherKind {
    Tag,
    Author,
    Authorship,
}

impl OtherKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tag => "tag",
            Self::Author => "author",
            Self::Authorship => "authorship",
        }
    }
}

/// What a link target names, once the whole revision DAG is consulted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkClass {
    /// Resolves to an entry that is still on the live frontier. A citation of
    /// a SUPERSEDED revision lands here too: it names exactly what its author
    /// read, and `wiki show` follows it forward by default.
    Live(usize),
    /// One id names several disconnected entries. Evidence, never breakage.
    Ambiguous(Vec<usize>),
    /// The target is a real revision, but every current state of its entry is
    /// archived — the live frontier no longer carries it. THIS is the class
    /// that means a reference went stale under someone.
    Retired(usize),
    /// Not a revision, but a legacy fragment anchor whose retained facts still
    /// name an entry. Reachable through the compatibility path only: the
    /// anchor stopped being a selector on 2026-08-18. A migration signal.
    Legacy { entries: Vec<usize>, retired: bool },
    /// No fragment at any revision, ever. A forward reference — the convention
    /// is to link liberally, so this is a TODO list, not a defect list.
    Unwritten(Option<OtherKind>),
}

impl LinkClass {
    /// True only for the one class that means something actually broke.
    pub const fn is_breakage(&self) -> bool {
        matches!(self, Self::Retired(_))
    }
}

/// One citation, kept with the revision that made it.
#[derive(Clone, Debug)]
pub struct LinkReference {
    pub source: Id,
    pub source_entry: usize,
    pub source_title: String,
    pub target: Id,
    pub class: LinkClass,
}

/// The whole frontier's outgoing citations, classified, plus the incoming
/// count each entry earned from that same walk.
#[derive(Clone, Debug, Default)]
pub struct LinkAudit {
    pub states: usize,
    pub total: usize,
    pub live: usize,
    pub ambiguous: Vec<LinkReference>,
    pub retired: Vec<LinkReference>,
    pub legacy: Vec<LinkReference>,
    pub unwritten: Vec<LinkReference>,
    /// Incoming resolved citations per entry index, self-citations excluded.
    pub incoming: Vec<usize>,
}

impl LinkAudit {
    pub fn breakage(&self) -> usize {
        self.retired.len()
    }
}

impl FrontierModel {
    /// Every legacy fragment anchor that still names an entry.
    ///
    /// The anchor is no longer a SELECTOR, but its facts were never removed —
    /// the store is append-only — so a reference written before the cutover can
    /// still be told apart from one that never had a target.
    fn index_anchors<P: TriblePattern>(
        facts: &P,
        selectors: &BTreeMap<Id, BTreeSet<usize>>,
    ) -> BTreeMap<Id, BTreeSet<usize>> {
        let mut anchors: BTreeMap<Id, BTreeSet<usize>> = BTreeMap::new();
        for (anchor, revision) in find!(
            (anchor: Id, revision: Id),
            pattern!(facts, [{ ?revision @ attrs::fragment: ?anchor }])
        ) {
            if let Some(entries) = selectors.get(&revision) {
                anchors
                    .entry(anchor)
                    .or_default()
                    .extend(entries.iter().copied());
            }
        }
        anchors
    }

    /// Classify one link target against the complete revision DAG.
    pub fn classify(&self, target: Id) -> LinkClass {
        match self.resolve(target) {
            LinkResolution::Unique(index) => {
                if self.entries[index].active {
                    LinkClass::Live(index)
                } else {
                    LinkClass::Retired(index)
                }
            }
            LinkResolution::Ambiguous(candidates) => LinkClass::Ambiguous(candidates),
            LinkResolution::Missing => match self.anchors.get(&target) {
                Some(entries) => LinkClass::Legacy {
                    entries: entries.iter().copied().collect(),
                    retired: !entries.iter().any(|index| self.entries[*index].active),
                },
                None => LinkClass::Unwritten(self.kinds.get(&target).copied()),
            },
        }
    }

    /// Walk every current state of every live entry once, classifying its
    /// outgoing citations and counting the incoming ones on the way.
    pub fn audit(&self) -> LinkAudit {
        let mut audit = LinkAudit {
            incoming: vec![0; self.entries.len()],
            ..LinkAudit::default()
        };
        for (index, entry) in self.entries.iter().enumerate().filter(|(_, e)| e.active) {
            for state in &entry.states {
                audit.states += 1;
                for &target in &state.links {
                    audit.total += 1;
                    let class = self.classify(target);
                    let reference = LinkReference {
                        source: state.revision,
                        source_entry: index,
                        source_title: state.title.clone(),
                        target,
                        class: class.clone(),
                    };
                    match class {
                        // A page citing itself does not make it referenced.
                        LinkClass::Live(target_entry) => {
                            audit.live += 1;
                            if target_entry != index {
                                audit.incoming[target_entry] += 1;
                            }
                        }
                        LinkClass::Ambiguous(_) => audit.ambiguous.push(reference),
                        LinkClass::Retired(_) => audit.retired.push(reference),
                        LinkClass::Legacy { .. } => audit.legacy.push(reference),
                        LinkClass::Unwritten(_) => audit.unwritten.push(reference),
                    }
                }
            }
        }
        audit
    }

    /// How many legacy fragment anchors the compatibility path can still name.
    ///
    /// Reported alongside the audit so a ZERO in the legacy class is readable:
    /// "no anchor is cited from the frontier" and "the anchor index is empty"
    /// are different findings, and a report that cannot tell them apart is a
    /// check that passes for the wrong reason.
    pub fn anchor_count(&self) -> usize {
        self.anchors.len()
    }

    /// Live entries nothing else at the frontier cites, cheapest form: the
    /// incoming counts the audit already produced.
    pub fn unreferenced(&self, audit: &LinkAudit) -> Vec<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(index, entry)| entry.active && audit.incoming[*index] == 0)
            .map(|(index, _)| index)
            .collect()
    }
}

/// Strict reference materialization for migrations and tests.
///
/// This deliberately resolves the supersession order from the complete fact
/// set. Durable application readers should use
/// [`materialize_indexed_collection`] instead.
pub fn materialize_collection(
    pile: &mut Pile,
    signer: &SigningKey,
) -> Result<(TribleSet, PileSnapshot)> {
    let collection = open_configured(pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
    let store_snapshot = pile.snapshot().context("freeze Wiki store snapshot")?;
    let (facts, _) = crate::storage::read_fact_collection(collection, &store_snapshot)
        .context("read Wiki collection")?;
    validate_catalog(&store_snapshot, &facts)?;
    Ok((facts, store_snapshot))
}

/// Capture one durable Wiki snapshot with shard-preserving facts and its
/// maintained supersession index.
///
/// Ordinary maintenance advances the fact derivation hops and latest relation
/// independently, then attaches them through one immutable snapshot. Positive
/// latest membership never admits states unseen by a lagging index. Normal
/// reads therefore never flatten the collection or validate a closed-world
/// catalog before asking their actual query.
pub async fn query_snapshot(pile: &mut Pile, signer: &SigningKey) -> Result<WikiQuerySnapshot> {
    let collection = open_configured(pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
    let policy = collection.policy(&pile.snapshot()?)?;
    let succinct = pile.derive::<SuccinctArchiveBlob>(collection, (), policy.clone())?;
    let rank9 = pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)?;
    let target = latest_collection(pile, signer.verifying_key())?;
    drop(
        pile.ensure(collection)
            .await
            .context("ensure Wiki source collection")?,
    );
    drop(
        pile.maintain(succinct)
            .await
            .context("maintain Wiki Succinct collection")?,
    );
    drop(
        pile.maintain(rank9)
            .await
            .context("maintain Wiki fact collection")?,
    );
    let store_snapshot = pile
        .maintain(target)
        .await
        .map_err(|error| anyhow!("maintain Wiki supersession index: {error}"))?;
    let facts = store_snapshot
        .collection(rank9)
        .context("observe Wiki fact collection")?
        .view::<FactArchive>()
        .context("read Wiki fact collection")?;
    let latest = store_snapshot
        .collection(target)
        .map_err(|error| anyhow!("observe Wiki supersession index: {error}"))?
        .view::<LatestIndex>()
        .map_err(|error| anyhow!("read Wiki supersession index: {error}"))?;
    Ok(WikiQuerySnapshot {
        facts,
        store_snapshot,
        latest,
    })
}

/// Strictly project and validate a complete Wiki snapshot.
///
/// This remains an explicit migration/import boundary for callers that need a
/// closed-world diagnostic oracle. It is deliberately not the ordinary query
/// path; normal commands use [`query_snapshot`] and query its [`FactArchive`]
/// directly.
pub async fn materialize_indexed_collection(
    pile: &mut Pile,
    signer: &SigningKey,
) -> Result<WikiSnapshot> {
    let collection = open_configured(pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
    let store_snapshot = pile.snapshot().context("freeze Wiki store snapshot")?;
    let (facts, cover) = crate::storage::read_fact_collection(collection, &store_snapshot)
        .context("read Wiki collection")?;
    let target = latest_collection(pile, signer.verifying_key())?;
    let maintained = pile
        .maintain_exact(target, &cover)
        .await
        .map_err(|error| anyhow!("maintain Wiki supersession index: {error}"))?;
    let latest = maintained
        .collection_exact(target, &cover)
        .map_err(|error| anyhow!("observe Wiki supersession index: {error}"))?
        .view::<LatestIndex>()
        .map_err(|error| anyhow!("read Wiki supersession index: {error}"))?;
    // This explicit migration/import projection retains the complete-facts
    // reference oracle; ordinary readers join the positive index directly.
    let catalog = validate_catalog(&store_snapshot, &facts)?;
    Ok(WikiSnapshot {
        facts,
        store_snapshot,
        latest,
        catalog,
    })
}

pub fn commit_collection(
    pile: &mut Pile,
    signer: &SigningKey,
    fragment: Fragment,
) -> Result<CollectionCommit> {
    // The signature is curation of this fragment into the collection. Author
    // attribution lives inside the revision artifact and is intentionally not
    // inferred from, or forced equal to, this signer.
    let collection = open_configured(pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
    pile.commit(collection, signer, fragment)
        .map_err(|error| anyhow!("commit Wiki collection fragment: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    use hifitime::Epoch;
    use triblespace::core::blob::MemoryBlobStore;

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

    fn latest_index(facts: &TribleSet) -> LatestIndex {
        let archive = facts.clone().to_blob();
        let observed = triblespace::core::collection::latest::derive_element(
            &archive,
            metadata::supersedes.id(),
        )
        .unwrap();
        LatestIndex::decode(&observed).unwrap()
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
    fn maintained_latest_matches_jit_across_fork_and_merge() {
        let signer = SigningKey::from_bytes(&[31; 32]);
        let (author_fragment, author) = author_record(&signer.verifying_key());
        let (root_fragment, root) = revision_record(draft(author, "root", [])).unwrap();
        let (left_fragment, left) = revision_record(draft(author, "left", [root])).unwrap();
        let (right_fragment, right) = revision_record(draft(author, "right", [root])).unwrap();
        let (merge_fragment, merge) =
            revision_record(draft(author, "merge", [left, right])).unwrap();

        let mut fork = author_fragment + root_fragment + left_fragment + right_fragment;
        let fork_index = latest_index(fork.facts());
        assert_eq!(
            entries(fork.facts(), &fork_index),
            load_catalog(fork.facts()).unwrap().revisions.all_entries()
        );
        assert_eq!(
            find!(id: Id, and!(fork_index.has(id),
                pattern!(fork.facts(), [{ ?id @ metadata::tag: &KIND_REVISION }]))
            )
            .collect::<BTreeSet<_>>(),
            BTreeSet::from([left, right])
        );

        fork += merge_fragment;
        let merge_index = latest_index(fork.facts());
        assert_eq!(
            entries(fork.facts(), &merge_index),
            load_catalog(fork.facts()).unwrap().revisions.all_entries()
        );
        assert_eq!(
            find!(id: Id, and!(merge_index.has(id),
                pattern!(fork.facts(), [{ ?id @ metadata::tag: &KIND_REVISION }]))
            )
            .collect::<BTreeSet<_>>(),
            BTreeSet::from([merge])
        );
    }

    #[test]
    fn facts_ahead_of_latest_stay_unseen_until_maintenance() {
        pollster::block_on(async {
            let signer = SigningKey::from_bytes(&[34; 32]);
            let (author_fragment, author) = author_record(&signer.verifying_key());
            let (root_fragment, root) = revision_record(draft(author, "root", [])).unwrap();
            let (next_fragment, next) = revision_record(draft(author, "next", [root])).unwrap();
            let (new_fragment, new) = revision_record(draft(author, "new entry", [])).unwrap();
            let mut store = MemoryRepo::default();
            let source = store
                .collection(
                    "latest-lag",
                    crate::collection_names::private_policy(signer.verifying_key()),
                )
                .unwrap();
            let target = store
                .derive::<LatestBlob>(
                    source,
                    metadata::supersedes.id(),
                    crate::collection_names::private_policy(signer.verifying_key()),
                )
                .unwrap();
            store
                .commit(source, &signer, author_fragment + root_fragment)
                .unwrap();
            let ready = store.maintain(target).await.unwrap();
            let lagging = ready
                .collection(target)
                .unwrap()
                .view::<LatestIndex>()
                .unwrap();
            store
                .commit(source, &signer, next_fragment + new_fragment)
                .unwrap();
            let snapshot = store.snapshot().unwrap();
            let facts = snapshot
                .collection(source)
                .unwrap()
                .view::<TribleSet>()
                .unwrap();
            let current = snapshot.collection(target).unwrap();
            assert_ne!(
                current.support(),
                snapshot.collection(source).unwrap().support()
            );
            let current = current.view::<LatestIndex>().unwrap();
            assert_eq!(
                entry(&facts, &current, root)
                    .unwrap()
                    .frontier
                    .iter()
                    .map(|r| r.id)
                    .collect::<Vec<_>>(),
                vec![root],
            );
            assert!(entry(&facts, &current, new).unwrap().frontier.is_empty());
            assert!(!exists!(
                (state: Id),
                and!(current.has(state), state.is(next.to_inline()))
            ));

            let ready = store.maintain(target).await.unwrap();
            let advanced = ready
                .collection(target)
                .unwrap()
                .view::<LatestIndex>()
                .unwrap();
            assert_eq!(
                entry(&facts, &advanced, root)
                    .unwrap()
                    .frontier
                    .iter()
                    .map(|r| r.id)
                    .collect::<Vec<_>>(),
                vec![next],
            );
            assert_eq!(entry(&facts, &advanced, new).unwrap().frontier[0].id, new);
            assert_eq!(
                entry(&facts, &lagging, root).unwrap().frontier[0].id,
                root,
                "maintenance must not mutate a frozen latest view"
            );
        });
    }

    #[test]
    fn latest_projection_converges_when_successors_arrive_before_ancestors() {
        use triblespace::core::collection::latest::{derive_element, empty, join};

        let author = genid().id;
        let (root_fragment, root) = revision_record(draft(author, "root", [])).unwrap();
        let (middle_fragment, middle) = revision_record(draft(author, "middle", [root])).unwrap();
        let (tip_fragment, tip) = revision_record(draft(author, "tip", [middle])).unwrap();
        let (fork_fragment, fork) = revision_record(draft(author, "fork", [root])).unwrap();
        let fragments = [root_fragment, middle_fragment, tip_fragment, fork_fragment];
        let mut complete = TribleSet::new();
        for fragment in &fragments {
            complete += fragment.facts().clone();
        }
        let expected =
            derive_element(&complete.clone().to_blob(), metadata::supersedes.id()).unwrap();

        for arrival in [[2, 1, 3, 0], [0, 1, 2, 3], [3, 0, 2, 1]] {
            let mut joined = empty();
            for position in arrival {
                let delta = derive_element(
                    &fragments[position].facts().clone().to_blob(),
                    metadata::supersedes.id(),
                )
                .unwrap();
                joined = join(&joined, &delta).unwrap();
            }
            assert_eq!(joined.bytes.as_ref(), expected.bytes.as_ref());
            let latest = LatestIndex::decode(&joined).unwrap();
            assert_eq!(
                entry(&complete, &latest, root)
                    .unwrap()
                    .frontier
                    .iter()
                    .map(|r| r.id)
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([tip, fork]),
            );
        }
    }

    #[test]
    fn supersedes_rejects_non_revision_sources_and_targets() {
        let legacy = genid().id;
        let outsider = genid().id;
        let base = entity! { ExclusiveId::force_ref(&legacy) @
            metadata::tag: &KIND_VERSION_ID,
            attrs::title: "legacy".to_blob().get_handle(),
            attrs::content: "body".to_blob().get_handle(),
            metadata::created_at: at(1.0),
        };

        let mut bad_source = base.facts().clone();
        bad_source += entity! { ExclusiveId::force_ref(&outsider) @
            metadata::supersedes: legacy,
        }
        .into_facts();
        assert!(load_catalog(&bad_source)
            .unwrap_err()
            .to_string()
            .contains("supersedes source"));

        let mut bad_target = base.into_facts();
        bad_target += entity! { ExclusiveId::force_ref(&legacy) @
            metadata::supersedes: outsider,
        }
        .into_facts();
        assert!(load_catalog(&bad_target)
            .unwrap_err()
            .to_string()
            .contains("supersedes target"));
    }

    #[test]
    fn exact_snapshot_index_does_not_advance_authority() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wiki.pile");
        File::create(&path).unwrap();
        let signer = SigningKey::from_bytes(&[32; 32]);
        let (author_fragment, author) = author_record(&signer.verifying_key());
        let (root_fragment, root) = revision_record(draft(author, "root", [])).unwrap();

        let mut pile = crate::storage::open_pile_strict(&path).unwrap();
        commit_collection(&mut pile, &signer, author_fragment + root_fragment).unwrap();
        let collection =
            open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key()).unwrap();
        let store_snapshot = pile.snapshot().unwrap();
        let instant = store_snapshot.instant();
        let cover_before = collection.admitted(&store_snapshot).unwrap();
        let snapshot =
            pollster::block_on(materialize_indexed_collection(&mut pile, &signer)).unwrap();
        let store_snapshot = pile.snapshot_at(instant).unwrap();
        let cover_after_index = collection.admitted(&store_snapshot).unwrap();
        assert_eq!(cover_after_index, cover_before);
        assert!(exists!(
            (id: Id),
            and!(snapshot.latest().has(id), id.is(root.to_inline()))
        ));

        pile.close().unwrap();
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
        let collection =
            crate::collection_names::open(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())
                .unwrap();
        pile.commit(collection, &signer, fragment).unwrap();
        let (facts, reader) = materialize_collection(&mut pile, &signer).unwrap();
        let order = latest_index(&facts);
        assert_eq!(
            cover_fragments(&reader, &facts, &order).unwrap(),
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
    fn curator_can_publish_another_authors_revision() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wiki.pile");
        File::create(&path).unwrap();

        let author_key = SigningKey::from_bytes(&[13; 32]);
        let curator_key = SigningKey::from_bytes(&[14; 32]);
        let (author_fragment, author) = author_record(&author_key.verifying_key());
        let (revision_fragment, revision) = revision_record(draft(author, "shared", [])).unwrap();

        let mut pile = crate::storage::open_pile_strict(&path).unwrap();
        commit_collection(&mut pile, &curator_key, author_fragment + revision_fragment).unwrap();
        let snapshot =
            pollster::block_on(materialize_indexed_collection(&mut pile, &curator_key)).unwrap();
        assert_eq!(
            snapshot
                .catalog()
                .revisions
                .revision(revision)
                .unwrap()
                .author,
            Some(author)
        );
        pile.close().unwrap();
    }

    #[test]
    fn read_model_ignores_unrelated_facts_but_rejects_unnormalized_tags() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wiki.pile");
        File::create(&path).unwrap();

        let signer = SigningKey::from_bytes(&[11; 32]);
        let (author_fragment, author) = author_record(&signer.verifying_key());
        let (revision_fragment, _) = revision_record(draft(author, "strict", [])).unwrap();
        let mut unexpected = author_fragment + revision_fragment;
        unexpected += entity! { metadata::description: "not Wiki state" };
        assert!(load_catalog(unexpected.facts()).is_ok());

        let mut bad_tag = Fragment::empty();
        let handle = bad_tag.put::<blobencodings::UTF8String, _>(" Mixed ".to_owned());
        bad_tag += entity! { metadata::name: handle };
        let tag = bad_tag.root().unwrap();
        let mut tagged = draft(author, "tagged", []);
        tagged.tags.insert(tag);
        let (revision, _) = revision_record(tagged).unwrap();
        bad_tag += author_record(&signer.verifying_key()).0;
        bad_tag += revision;
        let mut pile = crate::storage::open_pile_strict(&path).unwrap();
        commit_collection(&mut pile, &signer, bad_tag).unwrap();
        let error = match pollster::block_on(materialize_indexed_collection(&mut pile, &signer)) {
            Ok(_) => panic!("unnormalized tag unexpectedly materialized"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("not normalized"));
        pile.close().unwrap();
    }

    #[test]
    fn strict_durable_read_rejects_missing_revision_payloads() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wiki.pile");
        File::create(&path).unwrap();

        let signer = SigningKey::from_bytes(&[12; 32]);
        let (author_fragment, author) = author_record(&signer.verifying_key());
        let (revision_fragment, _) = revision_record(draft(author, "missing", [])).unwrap();
        let complete = author_fragment + revision_fragment;
        let missing =
            Fragment::from_facts_and_blobs(complete.facts().clone(), MemoryBlobStore::new());

        let mut pile = crate::storage::open_pile_strict(&path).unwrap();
        commit_collection(&mut pile, &signer, missing).unwrap();
        let error = match pollster::block_on(materialize_indexed_collection(&mut pile, &signer)) {
            Ok(_) => panic!("missing revision payload unexpectedly materialized"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("read Wiki revision"));
        pile.close().unwrap();
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
        assert_eq!(
            model
                .revision(second)
                .unwrap()
                .supersedes
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![first]
        );
        assert!(!model.revision(first).unwrap().is_native());
        let entry = model.entry_containing(second).unwrap();
        assert_eq!(
            entry
                .frontier
                .iter()
                .map(|head| head.id)
                .collect::<Vec<_>>(),
            vec![second]
        );
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

    /// THE NEGATIVE CONTROL. A checker that reports zero problems on a real
    /// corpus proves nothing unless a known-broken reference makes it fire and
    /// a known-good one does not, so this fixture contains one of each and
    /// pins every class between them.
    ///
    /// Built as one pile because the classifier reads content out of blobs:
    /// links are reproduced from admitted text, never asserted as facts.
    #[test]
    fn the_audit_separates_breakage_from_a_forward_reference() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.pile");
        File::create(&path).unwrap();
        let signer = SigningKey::from_bytes(&[21; 32]);
        let (author_fragment, author) = author_record(&signer.verifying_key());
        let (archived_tag, archived, _) = tag_record("archived").unwrap();

        // A page that is still on the frontier: linking to it is FINE.
        let (live_fragment, live) = revision_record(draft(author, "live page", [])).unwrap();
        // A page whose only current state is archived: linking to it is the
        // one thing here that is actually broken.
        let mut retired_draft = draft(author, "retired page", []);
        retired_draft.tags.insert(archived);
        let (retired_fragment, retired) = revision_record(retired_draft).unwrap();
        // A legacy anchor: not a selector since 2026-08-18, but its facts are
        // still here, so a reference to it is reachable through the old path.
        let anchor = genid().id;
        let legacy_version = genid().id;
        let mut legacy_fragment = Fragment::empty();
        let legacy_title: TextHandle = legacy_fragment.put("legacy page".to_owned());
        let legacy_content: TextHandle = legacy_fragment.put("legacy body".to_owned());
        legacy_fragment += entity! { ExclusiveId::force_ref(&legacy_version) @
            metadata::tag: &KIND_VERSION_ID,
            attrs::fragment: anchor,
            attrs::title: legacy_title,
            attrs::content: legacy_content,
            metadata::created_at: at(1.0),
        };
        // An id nobody ever minted a fragment for.
        let unwritten = Id::from_hex("11111111111111111111111111111111").unwrap();

        let citing = format!(
            "ok #link(\"wiki:{live:x}\")[live]\n\
             broken #link(\"wiki:{retired:x}\")[retired]\n\
             legacy #link(\"wiki:{anchor:x}\")[anchor]\n\
             todo #link(\"wiki:{unwritten:x}\")[unwritten]\n\
             wrong kind #link(\"wiki:{archived:x}\")[a tag]\n"
        );
        let (citer_fragment, citer) = revision_record(RevisionDraft {
            title: "citing page".to_owned(),
            content: citing,
            tags: BTreeSet::new(),
            predecessors: BTreeSet::new(),
            author,
            authored_at: at(2.0),
        })
        .unwrap();

        let mut fragment = author_fragment + archived_tag;
        fragment += live_fragment;
        fragment += retired_fragment;
        fragment += legacy_fragment;
        fragment += citer_fragment;

        let mut pile = crate::storage::open_pile_strict(&path).unwrap();
        let collection =
            crate::collection_names::open(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())
                .unwrap();
        pile.commit(collection, &signer, fragment).unwrap();
        let (facts, reader) = materialize_collection(&mut pile, &signer).unwrap();
        let order = latest_index(&facts);
        let model = FrontierModel::load(&reader, &facts, &order).unwrap();

        let index_of = |target: Id| match model.resolve(target) {
            LinkResolution::Unique(index) => index,
            other => panic!("expected one entry for {target:x}, got {other:?}"),
        };
        // The good reference does not fire, and the broken one does.
        assert_eq!(model.classify(live), LinkClass::Live(index_of(live)));
        assert!(!model.classify(live).is_breakage());
        assert_eq!(
            model.classify(retired),
            LinkClass::Retired(index_of(retired))
        );
        assert!(model.classify(retired).is_breakage());
        // Never written is a TODO, not a defect.
        assert_eq!(model.classify(unwritten), LinkClass::Unwritten(None));
        assert!(!model.classify(unwritten).is_breakage());
        // Naming a tag is a different mistake from naming nothing.
        assert_eq!(
            model.classify(archived),
            LinkClass::Unwritten(Some(OtherKind::Tag))
        );
        // The anchor is reachable only through the compatibility path.
        assert_eq!(
            model.classify(anchor),
            LinkClass::Legacy {
                entries: vec![index_of(legacy_version)],
                retired: false,
            }
        );

        let audit = model.audit();
        assert_eq!(audit.live, 1);
        assert_eq!(audit.retired.len(), 1);
        assert_eq!(audit.retired[0].source, citer);
        assert_eq!(audit.retired[0].target, retired);
        assert_eq!(audit.legacy.len(), 1);
        assert_eq!(audit.unwritten.len(), 2);
        assert!(audit.ambiguous.is_empty(), "one target, one entry, no fork");
        // The archived page is not a SOURCE either: only the live frontier is
        // walked, so retiring a page does not resurrect its own citations.
        assert_eq!(audit.states, 3, "live, legacy and citing pages only");

        // The orphan direction falls out of the same walk: the citer is cited
        // by nobody, and the live page it cites is not an orphan.
        let unreferenced: BTreeSet<Id> = model
            .unreferenced(&audit)
            .into_iter()
            .map(|index| model.entries[index].label)
            .collect();
        assert!(unreferenced.contains(&citer));
        assert!(!unreferenced.contains(&live));
        pile.close().unwrap();
    }

    /// A page citing ITSELF is not a page anyone linked to.
    #[test]
    fn a_self_citation_does_not_make_an_entry_referenced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("self.pile");
        File::create(&path).unwrap();
        let signer = SigningKey::from_bytes(&[22; 32]);
        let (author_fragment, author) = author_record(&signer.verifying_key());
        let (root_fragment, root) = revision_record(draft(author, "root", [])).unwrap();
        let (successor_fragment, _) = revision_record(RevisionDraft {
            title: "root".to_owned(),
            content: format!("see #link(\"wiki:{root:x}\")[my own first draft]\n"),
            tags: BTreeSet::new(),
            predecessors: BTreeSet::from([root]),
            author,
            authored_at: at(2.0),
        })
        .unwrap();

        let mut pile = crate::storage::open_pile_strict(&path).unwrap();
        let collection =
            crate::collection_names::open(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())
                .unwrap();
        pile.commit(
            collection,
            &signer,
            author_fragment + root_fragment + successor_fragment,
        )
        .unwrap();
        let (facts, reader) = materialize_collection(&mut pile, &signer).unwrap();
        let order = latest_index(&facts);
        let model = FrontierModel::load(&reader, &facts, &order).unwrap();
        let audit = model.audit();
        assert_eq!(audit.live, 1, "the citation resolves");
        assert_eq!(audit.incoming, vec![0], "but not as an incoming reference");
        assert_eq!(model.unreferenced(&audit).len(), 1);
        pile.close().unwrap();
    }

    /// The audit is READ-ONLY, and this compares the pile's bytes to prove it.
    ///
    /// The real corpus is written by other windows while a report runs, so its
    /// size moving proves nothing either way; a pile nobody else holds is the
    /// only place the claim can actually be tested. Byte equality rather than a
    /// digest: it is a small file and an exact comparison cannot be fooled.
    #[test]
    fn the_audit_leaves_the_pile_byte_identical() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("readonly.pile");
        File::create(&path).unwrap();
        let signer = SigningKey::from_bytes(&[23; 32]);
        let (author_fragment, author) = author_record(&signer.verifying_key());
        let (root_fragment, root) = revision_record(draft(author, "root", [])).unwrap();
        let (citer_fragment, _) = revision_record(RevisionDraft {
            title: "citer".to_owned(),
            content: format!("#link(\"wiki:{root:x}\")[root]\n"),
            tags: BTreeSet::new(),
            predecessors: BTreeSet::new(),
            author,
            authored_at: at(2.0),
        })
        .unwrap();
        let mut pile = crate::storage::open_pile_strict(&path).unwrap();
        let collection =
            crate::collection_names::open(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())
                .unwrap();
        pile.commit(
            collection,
            &signer,
            author_fragment + root_fragment + citer_fragment,
        )
        .unwrap();
        pile.close().unwrap();
        let before = std::fs::read(&path).unwrap();

        // Exactly what `wiki links` and `wiki check` do, and nothing else.
        let mut pile = crate::storage::open_pile_strict(&path).unwrap();
        let (facts, reader) = materialize_collection(&mut pile, &signer).unwrap();
        let order = latest_index(&facts);
        let model = FrontierModel::load(&reader, &facts, &order).unwrap();
        let audit = model.audit();
        let _ = model.unreferenced(&audit);
        pile.close().unwrap();

        assert_eq!(audit.live, 1, "the fixture must actually have been read");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "auditing links must not append a single byte"
        );
    }
}
