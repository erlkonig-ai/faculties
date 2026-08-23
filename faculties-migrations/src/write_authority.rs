//! Add the current Faculties build's team-of-one WRITE bootstrap.
//!
//! Existing named collections predate the positive authority ledger. Their
//! signed commits are intact, but a strict reader quite correctly treats them
//! as inert until the team root says who may WRITE each exact resource. This
//! migration appends only those grants. It never re-signs a target commit,
//! rewrites data, or derives grant targets from whatever happens to be in the
//! pile.

use std::path::Path;

use anyhow::{bail, Context, Result};
use triblespace::core::collection::CollectionCommit;
use triblespace::core::id::Id;
use triblespace::core::trible::Fragment;

use faculties::storage::{
    ensure_team_of_one_write_authority, load_signer, open_pile_strict,
    plan_team_of_one_write_authority, TeamOfOneWriteAuthorityReport,
};

fn finish<T>(pile: triblespace::core::repo::pile::Pile, result: Result<T>) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close WRITE-authority pile")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing pile also failed: {close_error}")))
        }
    }
}

/// Inspect the exact grants this build needs without touching the pile.
pub fn plan(pile: &Path, key: Option<&Path>) -> Result<TeamOfOneWriteAuthorityReport> {
    let signer = load_signer(pile, key)
        .context("load the durable team-of-one signer; WRITE authority never mints an identity")?;
    let mut store = open_pile_strict(pile)?;
    let result = plan_team_of_one_write_authority(&mut store, &signer);
    finish(store, result)
}

/// Append only the missing canonical self-WRITE grants.
pub fn publish(pile: &Path, key: Option<&Path>) -> Result<TeamOfOneWriteAuthorityReport> {
    let signer = load_signer(pile, key)
        .context("load the durable team-of-one signer; WRITE authority never mints an identity")?;
    let mut store = open_pile_strict(pile)?;
    let result = ensure_team_of_one_write_authority(&mut store, &signer);
    finish(store, result)
}

/// Require the closed WRITE manifest before a read-only migration plan.
///
/// A strict collection read correctly treats pre-authority COMMITs as inert.
/// Returning an empty plan in that state would therefore be a lie, not a dry
/// run. Mutating migration entry points call [`publish`] first; read-only plans
/// use this guard and tell the operator which additive prerequisite is missing.
pub(crate) fn require_initialized(pile: &Path, key: Option<&Path>) -> Result<()> {
    let report = plan(pile, key)?;
    if report.missing() != 0 {
        bail!(
            "cannot plan against WRITE-authorized faculty state: {} of {} configured grants are \
             missing; first run `migrations --pile {} faculty-write-authority` (add `--key` when \
             using a non-default signer)",
            report.missing(),
            report.rows().len(),
            pile.display(),
        );
    }
    Ok(())
}

/// Publish migration fragments after the migration boundary has initialized
/// the build's closed WRITE-grant manifest.
///
/// This deliberately lives in `faculties-migrations`, not in ordinary
/// storage publication. A normal faculty write without authority must fail;
/// only bootstrap and migration are allowed to create the initial grants.
pub fn publish_fragments(
    pile: &Path,
    key: Option<&Path>,
    scope: Id,
    fragments: impl IntoIterator<Item = Fragment>,
) -> Result<Vec<CollectionCommit>> {
    publish(pile, key).context("initialize WRITE authority before migration publication")?;
    faculties::storage::publish_fragments(pile, key, scope, fragments)
}
