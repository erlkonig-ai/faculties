//! Bridge pre-2026-08-18 Posture findings onto their content-located identity.
//!
//! Findings used to be identified by `(modality, path, commit:path:line,
//! value)`. Commit surgery destroyed that — a rebase gives the same material a
//! new `commit:path:line`, hence a new id, so every Decide resolution silently
//! stopped applying. Identity is now `(modality, carrier, inner locator)`,
//! where the carrier is content-addressed.
//!
//! The store is append-only, so nothing here deletes or rewrites a legacy
//! record. What it writes is a BRIDGE: "this old occurrence id turned out to be
//! that content-located finding", which is what lets an already-resolved
//! `benign` outcome keep applying across the identity change. Posture consults
//! bridges when it decides whether a finding is settled.
//!
//! What can be bridged, and what honestly cannot:
//!
//! - **Literal-pinned attribute findings** — always. The judgement is about the
//!   declaration itself, and the legacy record carries the declaration's exact
//!   normalized text, its path and its ordinal, which is the whole new
//!   coordinate. No repository needed.
//! - **Protected-term findings** — only where the audited repository is still
//!   on this machine at the path the scan recorded AND still has the commit.
//!   The new id is a byte range in a git blob, and neither the blob nor the
//!   range is recoverable from `commit:path:line` alone. A finding whose commit
//!   was rebased away is exactly the case that motivated the redesign, and it
//!   is unrecoverable by construction: nothing in the pile says what the
//!   material was, only where a vanished commit put it.
//! - **File-scan findings** (OOXML, EXIF, PDF) — not at all. Their carrier is a
//!   BLAKE3 hash over the container member posture extracted, and a legacy
//!   record stores neither the member nor its bytes. Re-run `posture scan` on
//!   the corpus; that is cheap, and it is the only honest path.
//!
//! Unresolved findings are reported one by one rather than counted away.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anybytes::View;
use anyhow::{anyhow, Context, Result};
use triblespace::core::blob::encodings::longstring::LongString;
use triblespace::core::collection::{Collection, CollectionCommit};
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStore, BlobStoreGet};
use triblespace::core::trible::{Fragment, TribleSet};
use triblespace::macros::entity;
use triblespace::prelude::{blobencodings, exists, find, inlineencodings, pattern};

use faculties::legacy_hint::open_scope;
use faculties::posture_finding::{
    commit_message_location, finding_id, git_bytes, git_probe, Carrier, GitObjects, Location,
};
use faculties::schemas::posture::{
    modality, posture, DEFAULT_SCAN_SCOPE_ID, KIND_FINDING, KIND_LEGACY_BRIDGE,
};
use faculties::storage::{load_signer, open_pile_strict, publish_fragment};

type TextHandle = Inline<Handle<LongString>>;

/// One legacy finding that could not be re-identified, and why.
#[derive(Clone, Debug)]
pub struct Unbridged {
    pub occurrence: Id,
    pub locator: String,
    pub reason: String,
}

/// The bridges a run would write, and everything it could not bridge.
#[derive(Debug)]
pub struct FindingBridgePlan {
    fragment: Fragment,
    examined: usize,
    bridged: BTreeMap<Id, Id>,
    already_bridged: usize,
    unbridged: Vec<Unbridged>,
}

impl FindingBridgePlan {
    /// Legacy findings inspected.
    pub const fn examined(&self) -> usize {
        self.examined
    }

    /// Legacy occurrence id → the content-located finding it turned out to be.
    pub const fn bridged(&self) -> &BTreeMap<Id, Id> {
        &self.bridged
    }

    /// Bridges the pile already carries from an earlier run.
    pub const fn already_bridged(&self) -> usize {
        self.already_bridged
    }

    pub fn unbridged(&self) -> &[Unbridged] {
        &self.unbridged
    }

    pub const fn fragment(&self) -> &Fragment {
        &self.fragment
    }
}

/// Read the Posture scan collection and work out every bridge it needs.
///
/// Pure: it opens repositories read-only and writes nothing.
pub fn plan(pile: &Path, key: Option<&Path>) -> Result<FindingBridgePlan> {
    let signer = load_signer(pile, key)?;
    let store = open_pile_strict(pile)?;
    let mut collection = open_scope(store, DEFAULT_SCAN_SCOPE_ID, signer);
    let result = (|| {
        let facts = collection
            .materialize()
            .context("materialize the Posture scan collection")?;
        let reader = collection
            .storage_mut()
            .reader()
            .context("open Posture scan blob reader")?;
        build(&facts, &reader)
    })();
    let close = collection.into_storage().close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(plan), Ok(())) => Ok(plan),
        (Ok(_), Err(error)) => Err(error.context("close Posture pile")),
        (Err(error), _) => Err(error),
    }
}

/// Write the bridges. Exact replay is idempotent, because both the blobs and
/// the collection record are content addressed.
pub fn publish(pile: &Path, key: Option<&Path>, plan: FindingBridgePlan) -> Result<Option<CollectionCommit>> {
    if plan.bridged.is_empty() {
        return Ok(None);
    }
    let mut fragment = plan.fragment;
    fragment.describe_with(entity! {
        metadata::description: "posture legacy finding identity bridges".to_owned(),
    });
    publish_fragment(pile, key, DEFAULT_SCAN_SCOPE_ID, fragment)
        .context("publish Posture finding bridges")
        .map(Some)
}

fn build(facts: &TribleSet, reader: &PileReader) -> Result<FindingBridgePlan> {
    let mut objects = GitObjects::default();
    let mut fragment = Fragment::empty();
    let mut bridged = BTreeMap::new();
    let mut unbridged = Vec::new();
    let mut already_bridged = 0usize;
    let mut examined = 0usize;
    let mut repositories: BTreeMap<PathBuf, bool> = BTreeMap::new();

    let legacy = find!(
        (finding: Id, occurrence: Id, locator: TextHandle, value: TextHandle),
        pattern!(facts, [{
            ?finding @
            metadata::tag: (&KIND_FINDING),
            posture::occurrence: ?occurrence,
            posture::locator: ?locator,
            posture::value: ?value
        }])
    )
    .collect::<BTreeSet<_>>();

    for (finding, occurrence, locator, value) in legacy {
        examined += 1;
        if exists!(pattern!(facts, [{
            _?bridge @
            metadata::tag: (&KIND_LEGACY_BRIDGE),
            posture::occurrence: (occurrence)
        }])) {
            already_bridged += 1;
            continue;
        }
        let locator = read_text(reader, locator, "legacy finding locator")?;
        let value = read_text(reader, value, "legacy finding value")?;
        let modality = find!(
            tag: Id,
            pattern!(facts, [{ (finding) @ metadata::tag: ?tag }])
        )
        .find(|tag| modality::is_known(*tag))
        .ok_or_else(|| anyhow!("legacy finding {finding:X} carries no known modality"))?;
        let repository = repository_of(facts, reader, finding)?;

        match locate(
            &mut objects,
            &mut repositories,
            modality,
            &locator,
            &value,
            repository.as_deref(),
        ) {
            Ok(location) => {
                let id = finding_id(modality, &location);
                fragment += entity! {
                    metadata::tag: KIND_LEGACY_BRIDGE,
                    posture::occurrence: occurrence,
                    posture::sighting_of: id,
                };
                bridged.insert(occurrence, id);
            }
            Err(reason) => unbridged.push(Unbridged {
                occurrence,
                locator,
                reason: reason.to_string(),
            }),
        }
    }

    Ok(FindingBridgePlan {
        fragment,
        examined,
        bridged,
        already_bridged,
        unbridged,
    })
}

/// The repository a git audit recorded as its document, when it named one.
fn repository_of(facts: &TribleSet, reader: &PileReader, finding: Id) -> Result<Option<PathBuf>> {
    let Some(document) = find!(
        document: Id,
        pattern!(facts, [{ (finding) @ posture::document: ?document }])
    )
    .next() else {
        return Ok(None);
    };
    let Some(path) = find!(
        path: TextHandle,
        pattern!(facts, [{ (document) @ posture::path: ?path }])
    )
    .next() else {
        return Ok(None);
    };
    Ok(Some(PathBuf::from(read_text(
        reader,
        path,
        "legacy document path",
    )?)))
}

/// Re-derive the content-addressed location a legacy record describes.
///
/// Every branch produces exactly what today's scanner would produce for the
/// same material — that is the point of a bridge, and why this calls the same
/// shared locators rather than reimplementing them.
fn locate(
    objects: &mut GitObjects,
    repositories: &mut BTreeMap<PathBuf, bool>,
    modality: Id,
    locator: &str,
    value: &str,
    repository: Option<&Path>,
) -> Result<Location> {
    if modality == modality::UNSAFE_ATTRIBUTE_ID {
        return unsafe_attribute_location(locator);
    }
    if modality != modality::PROTECTED_TERM {
        return Err(anyhow!(
            "a container member's hash is not recoverable from a legacy record; re-run `posture scan` on the corpus"
        ));
    }
    let repository = repository.ok_or_else(|| anyhow!("legacy finding names no repository"))?;
    if !*repositories
        .entry(repository.to_path_buf())
        .or_insert_with(|| repository.join(".git").exists())
    {
        return Err(anyhow!(
            "audited repository is not on this machine at {}",
            repository.display()
        ));
    }

    let (kind, rest) = locator
        .split_once(' ')
        .ok_or_else(|| anyhow!("unrecognized legacy locator"))?;
    let (coordinate, _) = rest.split_once("  ").unwrap_or((rest, ""));
    let (sha, coordinate) = coordinate
        .split_once(':')
        .ok_or_else(|| anyhow!("legacy locator names no commit"))?;
    if git_probe(
        repository,
        &["rev-parse", "--verify", "--quiet", &format!("{sha}^{{commit}}")],
        &[1],
    )?
    .is_none()
    {
        return Err(anyhow!(
            "commit {sha} is gone (rewritten or collected); the material it held is not recoverable from the record"
        ));
    }

    match kind {
        "message" => {
            let line = coordinate
                .parse::<usize>()
                .map_err(|_| anyhow!("legacy message locator names no line"))?;
            let body = git_bytes(repository, &["log", "-1", "--format=%B", sha])?;
            let body = String::from_utf8_lossy(&body).into_owned();
            let mut offset = 0usize;
            for (index, raw) in body.split_inclusive('\n').enumerate() {
                if index + 1 == line {
                    let text = raw.trim_end_matches(['\n', '\r']);
                    return Ok(commit_message_location(sha, offset, text, index, value));
                }
                offset += raw.len();
            }
            Err(anyhow!("commit {sha} no longer has line {line}"))
        }
        "path" => {
            let (_, path) = coordinate
                .split_once(':')
                .ok_or_else(|| anyhow!("legacy path locator names no path"))?;
            let carrier = match objects.blob_at(repository, sha, path)? {
                Some(oid) => Carrier::GitBlob(oid),
                None => Carrier::Commit(sha.to_owned()),
            };
            Ok(Location::field(carrier, path.to_owned()))
        }
        "patch" => {
            // `{patch_path}:{line}:diff-{n}`, or `{patch_path}:diff-{n}` when
            // the hunk header was unreadable.
            let (head, _) = coordinate
                .rsplit_once(':')
                .ok_or_else(|| anyhow!("legacy patch locator has no diff position"))?;
            match head.rsplit_once(':').and_then(|(path, line)| {
                line.parse::<u64>().ok().map(|line| (path.to_owned(), line))
            }) {
                Some((patch_path, line)) => {
                    let source = patch_path
                        .strip_prefix("a/")
                        .or_else(|| patch_path.strip_prefix("b/"))
                        .unwrap_or(&patch_path)
                        .to_owned();
                    objects.locate(repository, sha, &source, line, value)
                }
                None => Ok(Location::field(
                    Carrier::Commit(sha.to_owned()),
                    coordinate.to_owned(),
                )),
            }
        }
        other => Err(anyhow!("unrecognized legacy locator kind {other:?}")),
    }
}

/// `rust-attribute-{added,removed} {path}#{ordinal}  {declaration}` is already
/// the complete new coordinate: the declaration's own bytes are the carrier,
/// and path plus ordinal are the position. No repository is involved.
fn unsafe_attribute_location(locator: &str) -> Result<Location> {
    let rest = locator
        .strip_prefix("rust-attribute-")
        .ok_or_else(|| anyhow!("unrecognized legacy attribute locator"))?;
    let (change, rest) = rest
        .split_once(' ')
        .ok_or_else(|| anyhow!("legacy attribute locator names no change"))?;
    if change != "added" && change != "removed" {
        return Err(anyhow!("unrecognized attribute change {change:?}"));
    }
    let (coordinate, declaration) = rest
        .split_once("  ")
        .ok_or_else(|| anyhow!("legacy attribute locator carries no declaration"))?;
    Ok(Location::field(
        Carrier::member(declaration.as_bytes()),
        format!("{change} {coordinate}"),
    ))
}

fn read_text(reader: &PileReader, handle: TextHandle, field: &str) -> Result<String> {
    let value: View<str> = reader
        .get(handle)
        .with_context(|| format!("read Posture {field}"))?;
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_literal_pin_bridges_without_a_repository() {
        let location = unsafe_attribute_location(
            "rust-attribute-added src/schema.rs#1  \"AAAA\" unsafe as legacy: ShortString;",
        )
        .unwrap();
        assert_eq!(
            location,
            Location::field(
                Carrier::member(b"\"AAAA\" unsafe as legacy: ShortString;"),
                "added src/schema.rs#1".to_owned()
            )
        );
        // The direction is part of the coordinate: clearing an addition must
        // not clear the later removal of the same declaration.
        let removed = unsafe_attribute_location(
            "rust-attribute-removed src/schema.rs#1  \"AAAA\" unsafe as legacy: ShortString;",
        )
        .unwrap();
        assert_ne!(location, removed);
        assert_eq!(location.carrier, removed.carrier);
    }

    #[test]
    fn a_malformed_legacy_locator_is_reported_not_guessed() {
        assert!(unsafe_attribute_location("rust-attribute-added src/schema.rs#1").is_err());
        assert!(unsafe_attribute_location("patch abc:1  x").is_err());
    }
}
