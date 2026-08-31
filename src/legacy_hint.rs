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
use triblespace::core::blob::IntoBlob;
use triblespace::core::collection::Collection;
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{
    self, BlobStoreGet, CommitHandle, PinSnapshotSource, SnapshotSource,
};
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
    let collection = crate::collection_names::open_configured(pile, scope, signer.verifying_key())
        .with_context(|| {
            format!(
                "open collection {}",
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

/// Whether one collection has no authority-admitted commits, or `None` if its
/// descriptor or records cannot be observed.
fn native_scope_is_empty(pile: &mut Pile, collection: Collection<SimpleArchive>) -> Option<bool> {
    let snapshot = pile.snapshot().ok()?;
    collection
        .admitted(&snapshot)
        .ok()
        .map(|cover| cover.is_empty())
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
    let snapshot = pile.snapshot().ok()?;

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
        let archive: SimpleArchiveBlob = match snapshot.get(commit) {
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
    let store_snapshot = pile.snapshot().ok()?;

    let mut head = None;
    for (branch, pin) in pins {
        let Ok(facts): Result<TribleSet, _> = store_snapshot.get(pin) else {
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

    /// A genuinely pre-cutover pile gets the one remaining branch-cutover
    /// advice. Descriptor-policy re-seating belongs to the active migration,
    /// not to this runtime hint.
    #[test]
    fn a_pre_cutover_pile_still_gets_the_cutover_advice() {
        let directory = TempDir::new().unwrap();
        let path = new_pile(&directory);
        write_legacy_branch(&path);

        let mut pile = Pile::open(&path).unwrap();
        let collection = current_collection(&mut pile, DEFAULT_SCOPE_ID);
        let hint = legacy_migration_hint(&mut pile, DEFAULT_SCOPE_ID, collection).unwrap();
        pile.close().unwrap();

        assert!(hint.contains("legacy-branches activate"), "{hint}");
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
