//! One in-place legacy migration per faculty.
//!
//! [`activate_cutover`](crate::disposable_cutover::activate) is the whole-pile
//! path: it builds every collection into a disposable sibling and atomically
//! replaces an unchanged live pile. This module is the narrower one — the
//! capability the fifteen faculty `migrate-legacy` subcommands used to carry
//! before every migration verb moved onto the `migrations` binary. It migrates
//! exactly one faculty's legacy branch, in place, and leaves the rest of the
//! pile alone. That matters for a partially-migrated pile, and for anyone who
//! wants to move one faculty and check the result before moving the rest.
//!
//! Every typed transform has the same shape — `plan(&FrozenSource)` whose
//! `verify_conservation` proves the produced fragments re-union to exactly the
//! original `TribleSet`, then `publish` into the faculty's scope — so the
//! surrounding safety argument is written once, here, rather than fifteen
//! times with fifteen slightly different amounts of checking:
//!
//! 1. Load the durable signer **first**. A missing identity fails before any
//!    legacy state is inspected and before the pile grows by a byte.
//! 2. Freeze the source. Every writer must already be stopped.
//! 3. Construct and validate the complete typed plan without writing.
//! 4. Initialize the closed faculty WRITE manifest, then materialize the
//!    target scope's current native value.
//! 5. Publish the already-validated plan. Publication is exact replay of content-addressed
//!    commits, so rerunning an interrupted migration appends nothing.
//! 6. Re-materialize and require the result to be **exactly** the prior native
//!    value union the planned facts — no more, no less.
//! 7. Re-freeze and require the legacy pin table to be byte-identical, which
//!    is what proves nothing wrote to the pile while this ran.
//!
//! The legacy branch is never deleted, consumed, or rewritten. It stays as
//! read-only evidence, and a second run of the same command is a no-op.

use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use triblespace::core::id::Id;
use triblespace::core::trible::TribleSet;

use faculties::schemas;
use faculties::storage::{load_signer, open_pile_strict};

use crate::collection_cutover::{freeze_source, FrozenSource};

macro_rules! faculties {
    ($( $variant:ident, $label:literal, $module:ident, $scope:expr, $facts:ident );+ $(;)?) => {
        /// One faculty whose pre-collection branch can be migrated on its own.
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
        pub enum Faculty {
            $( #[doc = concat!("The `", $label, "` collection.")] $variant ),+
        }

        impl Faculty {
            /// Every migratable faculty, in the order `legacy-branches plan` lists them.
            pub const ALL: &'static [Faculty] = &[ $( Faculty::$variant ),+ ];

            /// The name used on the command line and in the aggregate plan.
            pub const fn label(self) -> &'static str {
                match self { $( Faculty::$variant => $label ),+ }
            }

            /// The native collection scope this faculty's facts land in.
            pub fn scope(self) -> Id {
                match self { $( Faculty::$variant => $scope ),+ }
            }
        }

        fn prepare<'a>(
            faculty: Faculty,
            source: &'a FrozenSource,
            pile: &'a Path,
            key: Option<&'a Path>,
        ) -> Result<Box<dyn FnOnce() -> Result<Published> + 'a>> {
            match faculty {
                $( Faculty::$variant => {
                    let plan = crate::$module::plan(source)
                        .with_context(|| format!("plan {} migration", $label))?;
                    let facts = plan.$facts().clone();
                    let report = format!("{:#?}", plan.report());
                    Ok(Box::new(move || {
                        let commits = crate::$module::publish(source, &plan, pile, key)
                            .with_context(|| format!("publish {} migration", $label))?;
                        Ok(Published {
                            facts,
                            commits: commits.len(),
                            report,
                        })
                    }))
                } ),+
            }
        }
    };
}

// label / module / target scope / accessor for the plan's complete fact value.
faculties! {
    Archive,   "archive",   archive_cutover,   schemas::blockdag::DEFAULT_SCOPE_ID,      materialized_facts;
    Atlas,     "atlas",     atlas_cutover,     schemas::atlas::DEFAULT_SCOPE_ID,         materialized_facts;
    Body,      "body",      body_cutover,      schemas::body::DEFAULT_SCOPE_ID,          materialized_facts;
    Cognition, "cognition", cognition_cutover, schemas::cognition::DEFAULT_SCOPE_ID,     materialized_facts;
    Comb,      "comb",      comb_cutover,      schemas::memory::DEFAULT_COMB_SCOPE_ID,   facts;
    Compass,   "compass",   compass_cutover,   schemas::compass::DEFAULT_SCOPE_ID,       materialized_facts;
    Decide,    "decide",    decide_cutover,    schemas::decide::DEFAULT_SCOPE_ID,        materialized_facts;
    Discord,   "discord",   discord_cutover,   schemas::discord::DEFAULT_SCOPE_ID,       materialized_facts;
    Files,     "files",     files_cutover,     schemas::files::DEFAULT_SCOPE_ID,         materialized_facts;
    Habit,     "habit",     habit_cutover,     schemas::habit::DEFAULT_SCOPE_ID,         materialized_facts;
    Headspace, "headspace", headspace_cutover, schemas::headspace::DEFAULT_SCOPE_ID,     materialized_facts;
    Mail,      "mail",      mail_cutover,      schemas::mail::DEFAULT_SCOPE_ID,          materialized_facts;
    Memory,    "memory",    memory_cutover,    schemas::memory::DEFAULT_SCOPE_ID,        materialized_facts;
    Message,   "message",   message_cutover,   schemas::message::DEFAULT_SCOPE_ID,       materialized_facts;
    Planner,   "planner",   planner_cutover,   schemas::planner::DEFAULT_SCOPE_ID,       materialized_facts;
    Posture,   "posture",   posture_cutover,   schemas::posture::DEFAULT_POLICY_SCOPE_ID, materialized_facts;
    Relations, "relations", relations_cutover, schemas::relations::DEFAULT_SCOPE_ID,     materialized_facts;
    Status,    "status",    status_cutover,    schemas::status::DEFAULT_SCOPE_ID,        materialized_facts;
    Teams,     "teams",     teams_cutover,     schemas::teams::DEFAULT_SCOPE_ID,         materialized_facts;
    Voice,     "voice",     voice_cutover,     schemas::voice::COLLECTION_SCOPE_ID,      materialized_facts;
    Web,       "web",       web_cutover,       schemas::web::DEFAULT_SCOPE_ID,           materialized_facts;
    Wiki,      "wiki",      wiki_cutover,      schemas::wiki::DEFAULT_SCOPE_ID,          materialized_facts;
}

impl std::fmt::Display for Faculty {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.label())
    }
}

impl FromStr for Faculty {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let wanted = value.trim().to_ascii_lowercase();
        Faculty::ALL
            .iter()
            .copied()
            .find(|faculty| faculty.label() == wanted)
            .ok_or_else(|| {
                anyhow!(
                    "unknown faculty '{value}'; expected one of {}",
                    Faculty::ALL
                        .iter()
                        .map(|faculty| faculty.label())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }
}

/// What one typed transform actually published.
struct Published {
    /// The plan's complete fact value — what the target scope must gain.
    facts: TribleSet,
    /// Native collection commits written (or re-proved, on a replay).
    commits: usize,
    /// The typed planner's own census, rendered in full.
    report: String,
}

/// Migrate one faculty's legacy branch into its native collection, in place.
///
/// Every writer on `pile` must be stopped. Running this twice is a no-op: the
/// second run republishes content-addressed commits that already exist and the
/// file does not grow.
pub fn migrate(faculty: Faculty, pile: &Path, key: Option<&Path>) -> Result<()> {
    // Authority first: a pile with no durable signer must fail here, before
    // the legacy source is read and before the file is touched.
    let signer = load_signer(pile, key).with_context(|| {
        format!(
            "load the durable signer for {}; migration never mints an ephemeral identity",
            pile.display()
        )
    })?;

    let source = freeze_source(pile).with_context(|| {
        format!(
            "freeze the legacy {faculty} source; every writer on {} must be stopped first",
            pile.display()
        )
    })?;
    let fingerprint = source.fingerprint();
    // Every typed conservation and shape check runs while the destination is
    // still byte-identical. The returned closure owns the validated plan and
    // is the only path that may publish it below.
    let publish = prepare(faculty, &source, pile, key)?;

    let scope = faculty.scope();
    let before = materialize(pile, scope, &signer)
        .with_context(|| format!("materialize the current native {faculty} collection"))?;

    let published = publish()?;

    let after = materialize(pile, scope, &signer)
        .with_context(|| format!("materialize the migrated native {faculty} collection"))?;
    let mut expected = before;
    expected += published.facts.clone();
    if after != expected {
        bail!(
            "{faculty} migration result is not exactly the prior native value union the planned \
             facts ({} facts after, {} expected); the published commits are content-addressed and \
             replay-safe, so stop every writer and rerun",
            after.len(),
            expected.len()
        );
    }

    let refreshed = freeze_source(pile).context("re-freeze the source to prove it was stopped")?;
    if refreshed.fingerprint() != fingerprint {
        bail!(
            "the legacy pin table changed while the {faculty} migration ran; the published commits \
             are replay-safe, so stop every writer and rerun"
        );
    }

    println!(
        "migrated {faculty}: {} native commit(s), {} fact(s) into scope {scope:X}",
        published.commits,
        published.facts.len(),
    );
    println!("{}", published.report);
    println!("legacy branch retained as read-only evidence; native commands no longer consult it");
    Ok(())
}

/// Read one scope's current native value through a short-lived pile handle.
fn materialize(pile: &Path, scope: Id, signer: &SigningKey) -> Result<TribleSet> {
    let mut storage = open_pile_strict(pile)?;
    let result = faculties::collection_names::open(&mut storage, scope, signer.clone())
        .materialize()
        .map_err(|error| anyhow!("materialize collection {scope:X}: {error}"));
    match (result, storage.close()) {
        (Ok(facts), Ok(())) => Ok(facts),
        (Ok(_), Err(error)) => Err(anyhow!("close pile: {error}")),
        (Err(error), _) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_label_round_trips_and_is_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for faculty in Faculty::ALL {
            assert!(seen.insert(faculty.label()), "duplicate {faculty}");
            assert_eq!(Faculty::from_str(faculty.label()).unwrap(), *faculty);
            assert_eq!(
                Faculty::from_str(&faculty.label().to_uppercase()).unwrap(),
                *faculty
            );
        }
        assert_eq!(seen.len(), Faculty::ALL.len());
    }

    #[test]
    fn unknown_faculty_names_the_alternatives() {
        let error = Faculty::from_str("nope").unwrap_err().to_string();
        assert!(error.contains("unknown faculty 'nope'"), "{error}");
        assert!(error.contains("compass"), "{error}");
    }

    /// Two faculties sharing a scope would make the additive verification in
    /// [`migrate`] check the wrong collection.
    #[test]
    fn every_faculty_has_its_own_scope() {
        let mut scopes = std::collections::BTreeSet::new();
        for faculty in Faculty::ALL {
            assert!(scopes.insert(faculty.scope()), "{faculty} shares a scope");
        }
    }

    /// The whole point of keeping this command: an old pile's facts become
    /// visible to the current faculty, the legacy branch survives untouched,
    /// and a second run is free.
    #[test]
    fn one_faculty_dispatch_is_additive_replayable_and_keeps_the_frozen_coordinate() {
        use std::fs::{self, File};

        use ed25519_dalek::SigningKey;
        use faculties::schemas::compass::{board, KIND_GOAL_ID, LEGACY_BRANCH_NAME};
        use faculties::storage::initialize_signer;
        use triblespace::core::metadata;
        use triblespace::macros::entity;
        use triblespace::prelude::*;

        use crate::collection_cutover::test_support::{
            TestBranchSpec, TestDeltaSpec, TestSourceSpec,
        };

        let directory = tempfile::TempDir::new().unwrap();
        let pile_path = directory.path().join("legacy.pile");
        let key_path = directory.path().join("legacy.key");
        File::create(&pile_path).unwrap();

        let goal = genid().id;
        let mut authored = Fragment::empty();
        let title = authored.put::<blobencodings::UTF8String, _>("preserve me".to_owned());
        authored += entity! { ExclusiveId::force_ref(&goal) @
            metadata::tag: &KIND_GOAL_ID,
            board::title: title,
        };
        let signer = initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let frozen = TestSourceSpec::new(vec![TestBranchSpec::new(
            LEGACY_BRANCH_NAME,
            Id::new([0x5A; 16]).unwrap(),
            SigningKey::from_bytes(&[0x5A; 32]),
            vec![TestDeltaSpec::authored(authored.clone(), "legacy goal")],
        )])
        .freeze(&pile_path)
        .unwrap();

        let scope = Faculty::Compass.scope();
        assert_eq!(
            materialize(&pile_path, scope, &signer).unwrap(),
            TribleSet::new(),
            "a legacy-only pile starts with an empty native collection"
        );
        let pins_before = frozen.source.legacy_pins().to_vec();

        prepare(
            Faculty::Compass,
            &frozen.source,
            &pile_path,
            Some(&key_path),
        )
        .unwrap()()
        .unwrap();

        let migrated = materialize(&pile_path, scope, &signer).unwrap();
        assert_eq!(
            migrated,
            authored.facts().clone(),
            "the native collection must hold exactly the legacy facts"
        );
        assert!(faculties::compass::goal_ids(&migrated).contains(&goal));

        assert_eq!(frozen.source.legacy_pins(), pins_before.as_slice());

        // And a second run publishes content-addressed commits that already
        // exist, so the file does not grow by a byte.
        let length = fs::metadata(&pile_path).unwrap().len();
        prepare(
            Faculty::Compass,
            &frozen.source,
            &pile_path,
            Some(&key_path),
        )
        .unwrap()()
        .unwrap();
        assert_eq!(fs::metadata(&pile_path).unwrap().len(), length);
        assert_eq!(materialize(&pile_path, scope, &signer).unwrap(), migrated);
    }

    /// A pile with no legacy branch for the requested faculty must say so
    /// rather than quietly succeeding.
    #[test]
    fn migrating_a_faculty_with_no_legacy_branch_reports_it() {
        use std::fs::File;

        use faculties::storage::initialize_signer;

        let directory = tempfile::TempDir::new().unwrap();
        let pile_path = directory.path().join("empty.pile");
        let key_path = directory.path().join("empty.key");
        File::create(&pile_path).unwrap();
        initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let before = std::fs::metadata(&pile_path).unwrap().len();

        let error = migrate(Faculty::Compass, &pile_path, Some(&key_path)).unwrap_err();
        assert!(
            format!("{error:#}").contains("no legacy Compass branch"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::metadata(&pile_path).unwrap().len(),
            before,
            "a rejected source must not initialize authority or grow the pile"
        );
    }
}
