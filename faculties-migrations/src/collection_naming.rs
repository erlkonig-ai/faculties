//! Re-seat every scoped root collection onto a name within a team.
//!
//! A root collection used to be anchored by an opaque minted scope id. It
//! discriminated roots correctly and told a reader nothing: every faculty
//! carried its scope as a hex constant in its own source, so "which collection
//! is this?" was answerable only by someone holding the code, and the pile
//! itself could say nothing about it. A root is now anchored by a name plus
//! its team's root public key, which makes the pile self-describing and lets a
//! collection authorize itself from its team root.
//!
//! That changes the descriptor's bytes and therefore its handle: current code
//! computes a handle no existing collection is under, and finds an empty
//! collection where the data is. This migration re-commits every collection's
//! state under its new handle.
//!
//! It is **additive**. A pile is append-only, so the old collections stay
//! exactly where they are and remain readable by the code that wrote them;
//! this appends new commits beside them. There is nothing to roll back to
//! because nothing is taken away. Run it on a copy first regardless -- an APFS
//! clone of a 12 GB pile costs about twenty milliseconds.
//!
//! What it does NOT migrate: derive records. A derivation is a computation
//! whose artifact is checkable, so a stale one is recomputed rather than
//! carried across, and derived collections rebuild on their next ensure.
//!
//! Leaving the old collections in place is deliberate but not the end state.
//! A pile is append-only, so nothing here can remove them; the reframe that
//! follows this migration rewrites the pile and is the step that drops them,
//! yielding one pile that is uniformly current-framed and carries only named
//! collections.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{bail, Context, Result};

use faculties::storage::{load_signer, open_pile_strict};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::{Blob, IntoBlob, TryFromBlob};
use triblespace::core::collection::reach;
pub use triblespace::core::collection::records::CollectionName;
use triblespace::core::collection::records::{
    collection_recipe, collection_representation, CollectionHandle,
};
use triblespace::core::collection::simplearchive_union::{self, TRIBLE_SET_UNION_RECIPE_V1};
use triblespace::core::collection::{
    discover_collection_records, CollectionCommit, CollectionRecord, CollectionStore,
};
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::genid::GenId;
use triblespace::core::metadata::MetaDescribe;
use triblespace::core::prelude::attributes;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStorePut};
use triblespace::core::trible::TribleSet;

use faculties::schemas::{
    atlas, blockdag, body, cognition, compass, decide, discord, embeddings, files, habit,
    headspace, mail, memory, message, orient, planner, posture, relations, status, teams, voice,
    web, wiki,
};

/// The anchor a root collection used to carry.
///
/// Retired from `triblespace` along with the scope model itself, and declared
/// here because this migration is the last thing that needs to read it. That
/// is what this crate is for: the faculties carry no migration surface, and a
/// retired attribute lives with the one transform that still understands it.
///
/// Minted with `trible genid` on 2026-08-07, retired 2026-08-20.
mod retired {
    use super::*;
    attributes! {
        "D3418873C70392E3ADAA05C00E11A583" unsafe as pub collection_scope: GenId;
    }
}

/// One root collection's move from an opaque scope to a name within a team.
#[derive(Clone, Debug)]
pub struct Rename {
    /// Handle the collection lives under today.
    pub old: CollectionHandle,
    /// Handle current code computes for the same meaning.
    pub new: CollectionHandle,
    /// The anchor it is leaving.
    pub scope: Id,
    /// The name it takes within its team.
    pub name: String,
    /// Signed states to re-commit under `new`.
    pub commits: usize,
}

/// What a run would do, or did.
#[derive(Clone, Debug, Default)]
pub struct CollectionNamingReport {
    /// Collections that can move, with their counts.
    pub renames: Vec<Rename>,
    /// Collections whose states are already all present under their new
    /// handle. The old collection is still there -- a pile is append-only and
    /// nothing removes it -- so a re-run keeps seeing it; this is how the run
    /// distinguishes "left to do" from "seen again".
    pub settled: Vec<Rename>,
    /// Collections this build cannot name, with the reason. Left alone rather
    /// than guessed at: a plausible name would turn an unreadable collection
    /// into a confidently mislabelled one, and nothing downstream could tell.
    pub unnamed: Vec<(CollectionHandle, String)>,
    /// Collections already anchored by a name.
    pub already_named: usize,
}

impl CollectionNamingReport {
    /// Total signed states the run would re-commit.
    pub fn commits(&self) -> usize {
        self.renames.iter().map(|rename| rename.commits).sum()
    }
}

/// Which name each scope takes.
///
/// Written against the schema constants rather than copied hex. A migration
/// that retyped 26 anchors by hand would be one transposition away from
/// re-seating a collection's states onto a name belonging to something else,
/// and that is not a failure a run could notice: both sides are well-formed,
/// so the states would simply land in the wrong collection and stay there.
///
/// Most faculties own one collection and keep their own name. The exceptions
/// own more than one and need a name each, which is why the charset allows
/// `-`.
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
        (memory::DEFAULT_SCOPE_ID, "memory"),
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

/// A scope this build cannot know about, named by whoever does.
///
/// The built-in table is written against schema constants, which reaches every
/// faculty in this repository and nothing outside it. A pile can hold
/// collections belonging to a consumer that lives elsewhere -- a private
/// repository, or one that simply is not a dependency -- and this crate has no
/// way to learn their names and no business depending on them to.
///
/// So the caller supplies them. That keeps a private consumer's constants in
/// its own repository, where they belong, instead of copying an id into a
/// public crate and hoping the two never drift.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtraName {
    /// The scope to name.
    pub scope: Id,
    /// What to call it.
    pub name: CollectionName,
}

/// One inline value for `attribute` on any entity in `facts`.
fn one(facts: &TribleSet, attribute: Id) -> Option<Id> {
    facts
        .iter()
        .find(|fact| *fact.a() == attribute)
        .and_then(|fact| fact.v::<GenId>().try_from_inline::<Id>().ok())
}

/// Read every collection the pile's records name, with the commits on it.
fn collections_with_commits<S>(
    store: &mut S,
) -> Result<BTreeMap<CollectionHandle, Vec<CollectionCommit>>>
where
    S: CollectionStore,
{
    let records = discover_collection_records(store).context("discover collection records")?;
    let mut by_collection: BTreeMap<CollectionHandle, Vec<CollectionCommit>> = BTreeMap::new();
    for commit in records.commits() {
        by_collection
            .entry(commit.collection())
            .or_default()
            .push(*commit);
    }
    Ok(by_collection)
}

/// The id a state will have once it is re-seated under `collection`.
fn expected_id(
    signer: &ed25519_dalek::SigningKey,
    collection: CollectionHandle,
    commit: &CollectionCommit,
) -> Id {
    CollectionCommit::sign(signer, collection, commit.data(), commit.metadata()).id()
}

/// The handle a descriptor's facts would have if stored.
///
/// Only the plan needs this, and only because a plan writes nothing: it has to
/// compare against what is already present without appending anything to find
/// out. `publish` takes its handle from what `put` hands back instead, which
/// is what makes a stored descriptor a consequence of naming one rather than a
/// second thing to remember.
fn prospective_handle(facts: &TribleSet) -> CollectionHandle {
    IntoBlob::<SimpleArchive>::to_blob(facts.clone()).get_handle()
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close collection-naming pile")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing collection-naming pile also failed: {close_error}"
        ))),
    }
}

/// Work out what would move, without writing.
pub fn plan(
    pile: &Path,
    key: Option<&Path>,
    extra: &[ExtraName],
) -> Result<CollectionNamingReport> {
    let signer = load_signer(pile, key).context("a re-commit needs the durable signing key")?;
    // A team of one: this pile's own durable identity is its team root. That
    // is the honest anchor for a pile nobody else writes to, and promoting it
    // to a real multi-node team later is a re-root -- a new collection reached
    // by deriving -- rather than a rename.
    let team = signer.verifying_key();
    let mut store = open_pile_strict(pile)?;
    let result = (|| {
        let by_collection = collections_with_commits(&mut store)?;
        let existing_by_collection = by_collection.clone();
        let reader = store.reader().context("open a blob reader")?;

        let mut report = CollectionNamingReport::default();
        let mut has_local_evidence = false;
        let mut has_foreign_legacy_evidence = false;
        for (old, commits) in by_collection {
            let Ok(blob) = reader.get::<Blob<SimpleArchive>, _>(old.transmute()) else {
                report
                    .unnamed
                    .push((old, "descriptor blob not resident".into()));
                continue;
            };
            let Ok(facts) = <TribleSet as TryFromBlob<SimpleArchive>>::try_from_blob(blob) else {
                report
                    .unnamed
                    .push((old, "descriptor does not decode".into()));
                continue;
            };
            let Some(scope) = one(&facts, retired::collection_scope.id()) else {
                if matches!(
                    triblespace::core::collection::descriptor::team(&facts),
                    Some(Ok(root)) if root == team
                ) {
                    has_local_evidence = true;
                }
                report.already_named += 1;
                continue;
            };
            let supplied = extra
                .iter()
                .find(|entry| entry.scope == scope)
                .map(|entry| entry.name.as_str().to_owned());
            let Some(name) = supplied.or_else(|| name_for(scope).map(str::to_owned)) else {
                report.unnamed.push((
                    old,
                    format!(
                        "this build has no name for scope {scope:X}; \
                         supply one with --name {scope:X}=<name> if you know it"
                    ),
                ));
                continue;
            };
            // Before explicit authority, the collection facade admitted only
            // the local signer. Preserve that historical boundary: a foreign
            // self-signed COMMIT beside the same opaque scope was inert and
            // must not become trusted merely because this migration re-signs
            // it.
            let commits = commits
                .into_iter()
                .filter(|commit| commit.public_key().raw == team.to_bytes())
                .collect::<Vec<_>>();
            if commits.is_empty() {
                has_foreign_legacy_evidence = true;
                report.unnamed.push((
                    old,
                    "recognized legacy scope has no COMMIT authored by the supplied team-of-one key"
                        .into(),
                ));
                continue;
            }
            has_local_evidence = true;
            // Only the SimpleArchive set-union kind is re-seated. Anything else
            // would need its own descriptor construction, and inventing one from a
            // representation this build may not know is exactly the guess the
            // `unnamed` list exists to refuse.
            let representation = one(&facts, collection_representation.id());
            let recipe = one(&facts, collection_recipe.id());
            if representation != Some(<SimpleArchive as MetaDescribe>::id())
                || recipe != Some(TRIBLE_SET_UNION_RECIPE_V1)
            {
                report.unnamed.push((
                    old,
                    "not a SimpleArchive set-union collection; no naming defined".into(),
                ));
                continue;
            }
            let named = CollectionName::new(&name).map_err(|error| {
                anyhow::anyhow!("{name} is not a legal collection name: {error}")
            })?;
            // The migration re-seats data into the collection the running build
            // would open, so this reach has to be the one
            // `collection_names::table` gives that name. It plans by name rather
            // than by scope and cannot consult the registry, so if a faculty is
            // ever published, this constant is the second place that has to move,
            // and a mismatch shows up as a rename to a handle nothing opens.
            let new = prospective_handle(
                simplearchive_union::descriptor(&named, team, reach::private()).facts(),
            );
            let rename = Rename {
                old,
                new,
                scope,
                name: name.clone(),
                commits: commits.len(),
            };
            // Signing is deterministic over the same transcript, so a state that
            // has already moved has a predictable commit id under the new handle.
            // If every one is present, this collection is settled rather than
            // pending, however many times the migration is re-run.
            let already: &[CollectionCommit] = existing_by_collection
                .get(&new)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let landed: BTreeSet<_> = already.iter().map(CollectionCommit::id).collect();
            if commits
                .iter()
                .all(|commit| landed.contains(&expected_id(&signer, new, commit)))
            {
                report.settled.push(rename);
            } else {
                report.renames.push(rename);
            }
        }
        if !has_local_evidence && has_foreign_legacy_evidence {
            bail!(
                "the supplied key authored none of this pile's recognized legacy collection \
                 states; refusing to create a parallel named team"
            );
        }
        Ok(report)
    })();
    finish_pile(store, result)
}

/// Append the named collections to the pile.
///
/// Every commit keeps its data and metadata handles and is signed afresh for
/// the new collection, because a commit's signature covers the collection it
/// is about. The blobs it points at are already resident and are not copied.
pub fn publish(
    pile: &Path,
    key: Option<&Path>,
    extra: &[ExtraName],
) -> Result<CollectionNamingReport> {
    let signer = load_signer(pile, key).context("a re-commit needs the durable signing key")?;
    let team = signer.verifying_key();
    let report = plan(pile, key, extra)?;

    let mut store = open_pile_strict(pile)?;
    let result = (|| {
        // Preflight authority before storing a descriptor or re-seating a
        // COMMIT. In particular, an existing foreign team must reject this
        // key before a newly written local root could make the key appear
        // legitimate to the guard.
        faculties::storage::ensure_team_of_one_write_authority(&mut store, &signer)
            .context("initialize WRITE authority for named faculty roots")?;
        let by_collection = collections_with_commits(&mut store)?;
        let mut written = BTreeSet::new();
        for rename in &report.renames {
            let named = CollectionName::new(&rename.name).expect("plan checked this");
            let descriptor = simplearchive_union::descriptor(&named, team, reach::private());
            // The handle comes from the store, not from a second hash beside it.
            let new = store
                .put::<SimpleArchive, _>(descriptor.facts().clone())
                .map_err(|error| anyhow::anyhow!("store the named descriptor: {error:?}"))?;
            if new != rename.new {
                bail!(
                    "descriptor handle moved between plan and publish for {}",
                    rename.name
                );
            }
            let existing: &[CollectionCommit] = by_collection
                .get(&rename.old)
                .map(Vec::as_slice)
                .unwrap_or_default();
            for commit in existing
                .iter()
                .filter(|commit| commit.public_key().raw == team.to_bytes())
            {
                let reseated =
                    CollectionCommit::sign(&signer, rename.new, commit.data(), commit.metadata());
                if written.insert(reseated.id()) {
                    store
                        .insert(CollectionRecord::Commit(reseated))
                        .map_err(|error| {
                            anyhow::anyhow!("append the re-seated commit: {error:?}")
                        })?;
                }
            }
        }
        Ok(())
    })();
    finish_pile(store, result).map(|()| report)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::{self, File};

    use ed25519_dalek::SigningKey;
    use faculties::storage::initialize_signer;
    use triblespace::core::metadata;
    use triblespace::core::trible::Fragment;
    use triblespace::macros::entity;

    fn legacy_descriptor(scope: Id, team: ed25519_dalek::VerifyingKey) -> Fragment {
        let mut descriptor = simplearchive_union::descriptor(
            &CollectionName::new("legacy-root").unwrap(),
            team,
            reach::private(),
        );
        descriptor += entity! { retired::collection_scope: &scope };
        descriptor
    }

    /// Every name in the table must be one the descriptor will accept.
    ///
    /// The charset is deliberately not restated here. Restating it would make
    /// this test agree with a copy of the rule rather than with the rule, and
    /// a copy is exactly what drifts.
    #[test]
    fn every_name_is_a_legal_collection_name() {
        for (_, name) in table() {
            CollectionName::new(name)
                .unwrap_or_else(|error| panic!("{name} is not a legal collection name: {error}"));
        }
    }

    /// Two scopes sharing a name would silently merge two collections into
    /// one, since a root's identity is exactly its name and team.
    #[test]
    fn names_are_unique() {
        let mut seen = BTreeSet::new();
        for (_, name) in table() {
            assert!(seen.insert(name), "{name} is claimed by two scopes");
        }
    }

    /// One scope appearing twice would make `name_for` depend on table order.
    #[test]
    fn scopes_are_unique() {
        let mut seen = BTreeSet::new();
        for (scope, _) in table() {
            assert!(seen.insert(scope), "{scope:X} appears twice in the table");
        }
    }

    #[test]
    fn wrong_key_is_rejected_before_collection_naming_mutates_the_pile() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("self.pile");
        let key_path = directory.path().join("self.key");
        File::create(&pile_path).unwrap();
        let local = initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let descriptor = legacy_descriptor(wiki::DEFAULT_SCOPE_ID, local.verifying_key());
        let mut pile = open_pile_strict(&pile_path).unwrap();
        simplearchive_union::publish_fragment_commit(
            &mut pile,
            &descriptor,
            entity! { _ @ metadata::tag: &Id::new([0x41; 16]).unwrap() },
            &local,
        )
        .unwrap();
        pile.close().unwrap();

        let foreign_pile = directory.path().join("foreign.pile");
        let foreign_key = directory.path().join("foreign.key");
        File::create(&foreign_pile).unwrap();
        initialize_signer(&foreign_pile, Some(&foreign_key)).unwrap();
        let before = fs::read(&pile_path).unwrap();

        let error = publish(&pile_path, Some(&foreign_key), &[]).unwrap_err();
        assert!(format!("{error:#}").contains("refusing to create a parallel named team"));
        assert_eq!(fs::read(&pile_path).unwrap(), before);
    }

    #[test]
    fn naming_reseats_only_the_historically_admitted_local_author() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("self.pile");
        let key_path = directory.path().join("self.key");
        File::create(&pile_path).unwrap();
        let local = initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let foreign = SigningKey::from_bytes(&[0x52; 32]);
        let descriptor = legacy_descriptor(wiki::DEFAULT_SCOPE_ID, local.verifying_key());
        let mut pile = open_pile_strict(&pile_path).unwrap();
        for (writer, marker) in [(&local, 0x61), (&foreign, 0x62)] {
            simplearchive_union::publish_fragment_commit(
                &mut pile,
                &descriptor,
                entity! { _ @ metadata::tag: &Id::new([marker; 16]).unwrap() },
                writer,
            )
            .unwrap();
        }
        pile.close().unwrap();

        let report = publish(&pile_path, Some(&key_path), &[]).unwrap();
        assert_eq!(report.renames.len(), 1);
        assert_eq!(report.renames[0].commits, 1);

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let records = discover_collection_records(&mut pile).unwrap();
        let moved = records
            .commits()
            .iter()
            .filter(|commit| commit.collection() == report.renames[0].new)
            .collect::<Vec<_>>();
        assert_eq!(moved.len(), 1);
        assert_eq!(moved[0].public_key().raw, local.verifying_key().to_bytes());
        pile.close().unwrap();
    }
}
