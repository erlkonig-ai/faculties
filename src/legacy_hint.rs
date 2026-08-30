//! The one place a faculty opens a native collection — and the one place a
//! pre-collection pile is told that its facts are still on a legacy branch.
//!
//! Every faculty reads native collection records now. A pile written before the
//! storage cutover still has all of its data, but it lives on named legacy
//! repository branches that no current command consults, so the faculty shows
//! an empty board, an empty wiki, an empty inbox — with nothing on screen to
//! suggest that a migration exists. That silence is the failure this module
//! closes.
//!
//! The check is identical for all migrated scopes ("this native scope has
//! no commits, but the legacy branch it replaced still has authored history"),
//! so it is implemented exactly once here and every faculty routes its
//! its descriptor registered through [`open_scope`]. The only per-faculty knowledge is
//! [`LEGACY_SOURCES`], a scope-id → legacy-branch-name table assembled from the
//! canonical constants in [`crate::schemas`]. The transforms that consume those
//! branches live in the separate `faculties-migrations` crate; this table is
//! what makes the warning possible without them.
//!
//! Deliberately absent from the table: the `orient` and `orient-state`
//! branches. Those are the migration's two reviewed *dispositions* — legacy
//! operational snapshots that are intentionally not translated into native
//! collections — so an empty native Orient scope is the expected steady state,
//! not a symptom, and `orient` already prints its own note-frontier guidance.
//!
//! The hint is advisory: it writes to stderr, never to stdout, never more than
//! once per scope per process, and any failure while probing is swallowed. A
//! diagnostic must not be able to break a command that would otherwise work.

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::sync::Mutex;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::utf8string::UTF8String;
use triblespace::core::blob::{Blob, IntoBlob, TryFromBlob};
use triblespace::core::collection::{
    Collection, CollectionRecord, CollectionStore, CollectionStoreExt,
};
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{self, BlobStore, BlobStoreGet, CommitHandle, PinSnapshotSource};
use triblespace::core::trible::TribleSet;

use crate::schemas;

/// Scope of the collection a faculty reads → name of the pre-collection branch
/// whose facts that scope replaced.
///
/// One row per migrated collection, in the same order as the aggregate
/// activation plan. Scopes without a legacy predecessor (embeddings, the
/// Posture scan scope, Orient) are deliberately absent: there is nothing to
/// point at, so they must stay silent.
pub const LEGACY_SOURCES: &[(Id, &str)] = &[
    (
        schemas::blockdag::DEFAULT_SCOPE_ID,
        schemas::blockdag::LEGACY_BRANCH_NAME,
    ),
    (
        schemas::memory::DEFAULT_COMB_SCOPE_ID,
        schemas::memory::LEGACY_COMB_BRANCH_NAME,
    ),
    (
        schemas::atlas::DEFAULT_SCOPE_ID,
        schemas::atlas::LEGACY_BRANCH_NAME,
    ),
    (
        schemas::body::DEFAULT_SCOPE_ID,
        schemas::body::LEGACY_BODY_BRANCH_NAME,
    ),
    (
        schemas::cognition::DEFAULT_SCOPE_ID,
        schemas::cognition::LEGACY_BRANCH_NAME,
    ),
    (
        schemas::compass::DEFAULT_SCOPE_ID,
        schemas::compass::LEGACY_BRANCH_NAME,
    ),
    (
        schemas::decide::DEFAULT_SCOPE_ID,
        schemas::decide::LEGACY_BRANCH_NAME,
    ),
    (
        schemas::discord::DEFAULT_SCOPE_ID,
        schemas::discord::LEGACY_BRANCH_NAME,
    ),
    (
        schemas::files::DEFAULT_SCOPE_ID,
        schemas::files::FILES_BRANCH_NAME,
    ),
    (
        schemas::habit::DEFAULT_SCOPE_ID,
        schemas::habit::LEGACY_BRANCH_NAME,
    ),
    (
        schemas::headspace::DEFAULT_SCOPE_ID,
        schemas::headspace::LEGACY_BRANCH_NAME,
    ),
    (
        schemas::mail::DEFAULT_SCOPE_ID,
        schemas::mail::LEGACY_BRANCH_NAME,
    ),
    (
        schemas::memory::DEFAULT_SCOPE_ID,
        schemas::memory::LEGACY_MEMORY_BRANCH_NAME,
    ),
    (
        schemas::message::DEFAULT_SCOPE_ID,
        schemas::message::LEGACY_BRANCH_NAME,
    ),
    (
        schemas::planner::DEFAULT_SCOPE_ID,
        schemas::planner::LEGACY_BRANCH_NAME,
    ),
    (
        schemas::posture::DEFAULT_POLICY_SCOPE_ID,
        schemas::posture::LEGACY_BRANCH_NAME,
    ),
    (
        schemas::relations::DEFAULT_SCOPE_ID,
        schemas::relations::LEGACY_BRANCH_NAME,
    ),
    (
        schemas::status::DEFAULT_SCOPE_ID,
        schemas::status::STATUS_BRANCH_NAME,
    ),
    (
        schemas::teams::DEFAULT_SCOPE_ID,
        schemas::teams::LEGACY_BRANCH_NAME,
    ),
    (
        schemas::voice::COLLECTION_SCOPE_ID,
        schemas::voice::LEGACY_BRANCH_NAME,
    ),
    (
        schemas::web::DEFAULT_SCOPE_ID,
        schemas::web::LEGACY_BRANCH_NAME,
    ),
    (
        schemas::wiki::DEFAULT_SCOPE_ID,
        schemas::wiki::LEGACY_BRANCH_NAME,
    ),
];

/// Upper bound on the legacy ancestry walk behind the hint.
///
/// The walk only runs on a pile that has no native commits in the scope at
/// all, so it happens at most once per scope per process and only before a
/// migration. The cap keeps even a pathological history from turning a
/// diagnostic into a stall; a capped count is reported as "at least".
const MAX_WALKED_COMMITS: usize = 100_000;

/// Open one native collection, warning first if this scope looks unmigrated.
///
/// This is the call every faculty makes before a store-centric collection
/// operation. It idempotently registers the descriptor and returns its handle;
/// the pile and signer remain owned by the caller.
pub fn open_scope(
    pile: &mut Pile,
    scope: Id,
    signer: &SigningKey,
) -> Result<Collection<SimpleArchive>> {
    let collection = crate::collection_names::open(pile, scope, signer.verifying_key())
        .with_context(|| {
            format!(
                "register collection {}",
                crate::collection_names::require_name(scope)
            )
        })?;
    warn_once(pile, scope, collection);
    Ok(collection)
}

/// Emit the hint for `scope` at most once per process, to stderr.
fn warn_once(pile: &mut Pile, scope: Id, collection: Collection<SimpleArchive>) {
    static WARNED: Mutex<Option<BTreeSet<Id>>> = Mutex::new(None);

    if !LEGACY_SOURCES.iter().any(|(known, _)| *known == scope) {
        return;
    }
    {
        let mut warned = match WARNED.lock() {
            Ok(warned) => warned,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !warned.get_or_insert_with(BTreeSet::new).insert(scope) {
            return;
        }
    }
    if let Some(hint) = legacy_migration_hint(pile, scope, collection) {
        eprintln!("{hint}");
    }
}

/// The advice an unmigrated pile needs for `scope`, or `None` when there is
/// nothing to say.
///
/// `None` — the quiet case, which is the overwhelmingly common one — covers:
/// a scope with no legacy predecessor, a native collection that already holds
/// commits, an absent legacy branch, a legacy branch with no head, a legacy
/// branch whose history carries no authored content, and every read failure
/// encountered while probing.
pub fn legacy_migration_hint(
    pile: &mut Pile,
    scope: Id,
    collection: Collection<SimpleArchive>,
) -> Option<String> {
    let branch_name = LEGACY_SOURCES
        .iter()
        .find(|(known, _)| *known == scope)
        .map(|(_, name)| *name)?;

    if !native_scope_is_empty(pile, collection)? {
        return None;
    }

    // TWO ways a collection can read as empty, and they want opposite advice.
    //
    // A pile that never cut over has its history in a legacy branch. A pile
    // that cut over but predates NAMING has its history in real native
    // collections that this build cannot address: they are anchored by the
    // retired scope, so a lookup by name finds nothing and the emptiness above
    // is an addressing failure rather than an absence. Such a pile usually
    // still carries the legacy branch as residue, so checking the branch first
    // confidently names a migration that already ran.
    //
    // Naming is named first when both hold: it is what makes the collections
    // readable at all.
    if any_scope_anchored_collection(pile)? {
        return Some(format!(
            "note: this pile's native `{branch_name}` collection cannot be found by name, but the pile holds collections anchored by the retired scope id.\n\
             note: a root collection is now named within a namespace, which changed its descriptor and so its identity; current faculties therefore look for a collection this pile does not have yet. Nothing has been lost — the existing collections are intact and the migration only adds beside them.\n\
             note: run `migrations --pile <this pile> collection-naming --dry-run` to see exactly what would move, and `migrations --pile <this pile> collection-naming` to migrate."
        ));
    }
    let (commits, capped) = legacy_authored_commits(pile, branch_name)?;
    if commits == 0 {
        return None;
    }

    let about = if capped {
        format!("at least {commits} authored commits")
    } else if commits == 1 {
        "1 authored commit".to_owned()
    } else {
        format!("{commits} authored commits")
    };
    Some(format!(
        "note: this pile's native `{branch_name}` collection has no commits, but its legacy `{branch_name}` branch still holds {about}.\n\
         note: current faculties read only native collections, so that history stays invisible until it is migrated. Nothing has been lost — the legacy branch is intact and migration only adds to it.\n\
         note: stop every writer on this pile, then run `migrations --pile <this pile> legacy-branches plan` to see exactly what would move, and `migrations --pile <this pile> legacy-branches activate` to migrate."
    ))
}

/// The anchor a root collection carried before it was named within a namespace.
///
/// A bare PROBE id, deliberately not a schema declaration: this crate no longer
/// knows what a scope MEANS, only that a descriptor still carrying one predates
/// naming. The transform that understands it lives in `faculties-migrations`,
/// and rebuilding scope-anchored descriptors from a name table here would drag
/// that migration surface back into the library it was moved out of.
///
/// Minted with `trible genid` on 2026-08-07, retired 2026-08-20.
const RETIRED_COLLECTION_SCOPE: Id =
    triblespace::macros::id_hex!("D3418873C70392E3ADAA05C00E11A583");

/// Whether any collection in this pile is still anchored by a scope.
///
/// Generic on purpose: the question is "does any descriptor here carry a
/// scope", never "is THIS faculty's old descriptor present". A name table would
/// answer only for collections this build happens to know, and would go stale
/// against a pile older or stranger than itself.
///
/// This runs only once a collection has already read as empty, so its cost
/// lands on a pile that is broken for the reader anyway; being able to say what
/// is wrong is worth more there than the scan it takes to find out.
fn any_scope_anchored_collection(pile: &mut Pile) -> Option<bool> {
    let mut collections = BTreeSet::new();
    for record in pile.records().ok()? {
        if let Ok(CollectionRecord::Commit(commit)) = record {
            collections.insert(commit.collection());
        }
    }
    let reader = pile.reader().ok()?;
    for collection in collections {
        // A descriptor that is absent or does not decode says nothing either
        // way, so it is skipped rather than treated as an answer.
        let Ok(blob) = reader.get::<Blob<SimpleArchive>, _>(collection.transmute()) else {
            continue;
        };
        let Ok(facts) = <TribleSet as TryFromBlob<SimpleArchive>>::try_from_blob(blob) else {
            continue;
        };
        if facts
            .iter()
            .any(|fact| *fact.a() == RETIRED_COLLECTION_SCOPE)
        {
            return Some(true);
        }
    }
    Some(false)
}

/// Whether one collection has no authority-admitted commits, or `None` if its
/// descriptor or records cannot be observed.
fn native_scope_is_empty(pile: &mut Pile, collection: Collection<SimpleArchive>) -> Option<bool> {
    pile.cover(collection).ok().map(|cover| cover.is_empty())
}

/// Count authored commits reachable from the head of the legacy branch named
/// `name`, and whether the walk hit [`MAX_WALKED_COMMITS`].
///
/// `None` means there is no such branch, it has no head, or the pile could not
/// be read. Contentless merge commits are ancestry, not authorship, so they
/// are walked but not counted — the same distinction the migration itself
/// makes.
fn legacy_authored_commits(pile: &mut Pile, name: &str) -> Option<(usize, bool)> {
    let head = legacy_branch_head(pile, name)?;
    let reader = pile.reader().ok()?;

    let mut seen: HashSet<CommitHandle> = HashSet::new();
    let mut queue: VecDeque<CommitHandle> = VecDeque::new();
    seen.insert(head);
    queue.push_back(head);

    let mut authored = 0;
    let mut walked = 0;
    while let Some(commit) = queue.pop_front() {
        walked += 1;
        if walked > MAX_WALKED_COMMITS {
            return Some((authored, true));
        }
        let archive: SimpleArchiveBlob = match reader.get(commit) {
            Ok(archive) => archive,
            Err(_) => continue,
        };
        let facts: TribleSet = match archive.try_from_blob() {
            Ok(facts) => facts,
            Err(_) => continue,
        };
        if facts.iter().any(|fact| fact.a() == &repo::content.id()) {
            authored += 1;
        }
        for fact in facts.iter() {
            if fact.a() == &repo::parent.id() {
                let parent: CommitHandle = *fact.v::<Handle<SimpleArchive>>();
                if seen.insert(parent) {
                    queue.push_back(parent);
                }
            }
        }
    }
    Some((authored, false))
}

type SimpleArchiveBlob = triblespace::core::blob::Blob<SimpleArchive>;

/// Resolve the head commit of the legacy branch named `name`.
///
/// Branch names live in the branch-pin blobs, so this reads every pin (there
/// are a few dozen at most) and matches on the intrinsic handle of the name
/// rather than decoding each one. A duplicated name is treated as "cannot
/// tell" and stays silent.
fn legacy_branch_head(pile: &mut Pile, name: &str) -> Option<CommitHandle> {
    let wanted: Inline<Handle<UTF8String>> = name.to_owned().to_blob().get_handle();
    let snapshot = pile.snapshot_pin_heads().ok()?;
    let pins: Vec<(Id, Inline<Handle<SimpleArchive>>)> = snapshot
        .iter_ordered()
        .filter_map(|raw| Some((Id::new(*raw)?, *snapshot.get(raw)?)))
        .collect();
    let reader = pile.reader().ok()?;

    let mut head = None;
    for (branch, pin) in pins {
        let Ok(facts): Result<TribleSet, _> = reader.get(pin) else {
            continue;
        };
        let Ok(entity) = repo::branch::branch_entity(&facts, branch) else {
            continue;
        };
        let named = facts.iter().any(|fact| {
            fact.e() == &entity
                && fact.a() == &metadata::name.id()
                && *fact.v::<Handle<UTF8String>>() == wanted
        });
        if !named {
            continue;
        }
        if head.is_some() {
            // Two branches claim this name; the migration would reject the
            // pile outright, and a diagnostic has no business guessing.
            return None;
        }
        head = facts
            .iter()
            .find(|fact| fact.e() == &entity && fact.a() == &repo::head.id())
            .map(|fact| *fact.v::<Handle<SimpleArchive>>());
    }
    head
}

#[cfg(test)]
mod tests {
    /// Authority used by these collection fixtures.
    fn test_authority() -> ed25519_dalek::VerifyingKey {
        signer().verifying_key()
    }

    use std::fs::File;

    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use triblespace::core::collection::simplearchive_union;
    use triblespace::macros::entity;
    use triblespace::prelude::*;

    use super::*;
    use crate::schemas::compass::{board, DEFAULT_SCOPE_ID, KIND_GOAL_ID};

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[0x37; 32])
    }

    fn goal_fragment(title: &str) -> Fragment {
        let mut fragment = Fragment::empty();
        let handle = fragment.put::<blobencodings::UTF8String, _>(title.to_owned());
        let goal = genid();
        fragment += entity! { &goal @
            metadata::tag: &KIND_GOAL_ID,
            board::title: handle,
        };
        fragment
    }

    /// Restore a byte-for-byte pile written by the v0.46 Repository API.
    ///
    /// Keeping the historical bytes as the oracle tests the reader boundary
    /// without retaining a second mutable legacy writer in test code.
    fn write_legacy_branch(path: &std::path::Path) {
        std::fs::write(
            path,
            include_bytes!("../tests/fixtures/legacy_compass_v046.pile"),
        )
        .unwrap();
    }

    fn new_pile(directory: &TempDir) -> std::path::PathBuf {
        let path = directory.path().join("hint.pile");
        File::create(&path).unwrap();
        path
    }

    fn current_collection(pile: &mut Pile, scope: Id) -> Collection<SimpleArchive> {
        crate::collection_names::open(pile, scope, test_authority()).unwrap()
    }

    #[test]
    fn hint_fires_when_native_scope_is_empty_and_legacy_branch_has_history() {
        let directory = TempDir::new().unwrap();
        let path = new_pile(&directory);
        write_legacy_branch(&path);

        let mut pile = Pile::open(&path).unwrap();
        let collection = current_collection(&mut pile, DEFAULT_SCOPE_ID);
        assert_eq!(native_scope_is_empty(&mut pile, collection), Some(true));
        let hint = legacy_migration_hint(&mut pile, DEFAULT_SCOPE_ID, collection)
            .expect("a legacy-only pile must say so");
        pile.close().unwrap();

        assert!(
            hint.contains("legacy `compass` branch still holds 1 authored commit"),
            "hint must state the count it found: {hint}"
        );
        assert!(
            hint.contains("legacy-branches activate"),
            "hint must name the command that fixes it: {hint}"
        );
        assert!(
            hint.contains("stop every writer"),
            "hint must name the precondition: {hint}"
        );
    }

    #[test]
    fn only_an_authority_commit_suppresses_the_legacy_hint() {
        let directory = TempDir::new().unwrap();
        let path = new_pile(&directory);
        write_legacy_branch(&path);

        let mut pile = Pile::open(&path).unwrap();
        let collection = current_collection(&mut pile, DEFAULT_SCOPE_ID);
        assert!(legacy_migration_hint(&mut pile, DEFAULT_SCOPE_ID, collection).is_some());
        let foreign = SigningKey::from_bytes(&[0x73; 32]);
        pile.commit(
            collection,
            &foreign,
            goal_fragment("inert foreign native goal"),
        )
        .unwrap();

        assert_eq!(
            native_scope_is_empty(&mut pile, collection),
            Some(true),
            "a foreign commit is resident but inert without a presentation"
        );

        pile.commit(
            collection,
            &signer(),
            goal_fragment("authority native goal"),
        )
        .unwrap();
        assert_eq!(
            native_scope_is_empty(&mut pile, collection),
            Some(false),
            "the descriptor authority's commit is admitted directly"
        );
        assert_eq!(
            legacy_migration_hint(&mut pile, DEFAULT_SCOPE_ID, collection),
            None
        );
        pile.close().unwrap();
    }

    /// A descriptor as a pile written before naming carries one: the current
    /// shape plus the retired scope anchor.
    ///
    /// Built from the raw retired attribute id rather than a declaration, for
    /// exactly the reason the probe is: this crate no longer knows what a scope
    /// means, and declaring it would pull a migration surface back into the
    /// library it was moved out of.
    fn scope_anchored_descriptor(scope: Id) -> Fragment {
        use triblespace::core::inline::encodings::genid::GenId;
        use triblespace::core::inline::IntoInline;
        use triblespace::core::trible::Trible;

        let current = crate::collection_names::root_descriptor(scope, test_authority());
        let root = ExclusiveId::force(current.root().expect("a descriptor has one root"));
        let mut facts = current.into_facts();
        facts.insert(&Trible::new(
            &root,
            &RETIRED_COLLECTION_SCOPE,
            &IntoInline::<GenId>::to_inline(scope),
        ));
        Fragment::rooted(*root, facts)
    }

    /// A pile that DID cut over but predates naming must not be told to run the
    /// cutover again. Its collections are real and full; they are simply not
    /// reachable by name, and the legacy branch it still carries is residue.
    #[test]
    fn a_pre_naming_pile_is_told_to_name_its_collections_not_to_cut_over_again() {
        let directory = TempDir::new().unwrap();
        let path = new_pile(&directory);
        // Residue: the branch a pre-naming pile still has lying around.
        write_legacy_branch(&path);

        let mut pile = Pile::open(&path).unwrap();
        // Real history, under the anchor that build used.
        simplearchive_union::publish_fragment_commit(
            &mut pile,
            &scope_anchored_descriptor(DEFAULT_SCOPE_ID),
            goal_fragment("a goal published before naming"),
            &signer(),
        )
        .unwrap();

        let collection = current_collection(&mut pile, DEFAULT_SCOPE_ID);
        let hint = legacy_migration_hint(&mut pile, DEFAULT_SCOPE_ID, collection)
            .expect("a pile whose collections cannot be found by name must say so");
        pile.close().unwrap();

        assert!(
            hint.contains("collection-naming"),
            "the naming migration is the one that applies: {hint}"
        );
        assert!(
            !hint.contains("legacy-branches activate"),
            "this pile already cut over; naming it again is not cutting it over: {hint}"
        );
        assert!(
            hint.contains("Nothing has been lost"),
            "naming is additive too, and the reader needs to know it: {hint}"
        );
    }

    /// The two arms are distinct: a genuinely pre-cutover pile still gets the
    /// cutover advice, because nothing in it is anchored by a scope.
    #[test]
    fn a_pre_cutover_pile_still_gets_the_cutover_advice() {
        let directory = TempDir::new().unwrap();
        let path = new_pile(&directory);
        write_legacy_branch(&path);

        let mut pile = Pile::open(&path).unwrap();
        assert_eq!(any_scope_anchored_collection(&mut pile), Some(false));
        let collection = current_collection(&mut pile, DEFAULT_SCOPE_ID);
        let hint = legacy_migration_hint(&mut pile, DEFAULT_SCOPE_ID, collection).unwrap();
        pile.close().unwrap();

        assert!(hint.contains("legacy-branches activate"), "{hint}");
        assert!(!hint.contains("collection-naming"), "{hint}");
    }

    #[test]
    fn hint_is_silent_without_a_legacy_branch_or_a_known_scope() {
        let directory = TempDir::new().unwrap();
        let path = new_pile(&directory);

        let mut pile = Pile::open(&path).unwrap();
        // A brand new pile has neither side.
        let compass = current_collection(&mut pile, DEFAULT_SCOPE_ID);
        assert_eq!(
            legacy_migration_hint(&mut pile, DEFAULT_SCOPE_ID, compass),
            None
        );
        // A scope with no legacy predecessor never speaks, even when empty.
        let orient = current_collection(&mut pile, crate::schemas::orient::DEFAULT_SCOPE_ID);
        assert_eq!(
            legacy_migration_hint(&mut pile, crate::schemas::orient::DEFAULT_SCOPE_ID, orient),
            None
        );
        pile.close().unwrap();
    }

    #[test]
    fn every_table_scope_is_distinct() {
        let mut scopes = BTreeSet::new();
        for (scope, name) in LEGACY_SOURCES {
            assert!(scopes.insert(*scope), "duplicate scope for `{name}`");
            assert!(!name.is_empty());
        }
        assert_eq!(scopes.len(), LEGACY_SOURCES.len());
    }
}
