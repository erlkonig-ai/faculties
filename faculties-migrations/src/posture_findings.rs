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
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::utf8string::UTF8String;
use triblespace::core::blob::encodings::UnknownBlob;
use triblespace::core::blob::Blob;
use triblespace::core::collection::{
    discover_collection_records, CollectionCommit, CollectionRecord, CollectionStore,
};
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::{BlobStoreGet, BlobStorePut, OfferCapture, SnapshotSource};
use triblespace::core::trible::{Fragment, TribleSet};
use triblespace::macros::entity;
use triblespace::prelude::{exists, find, pattern};

use faculties::posture_finding::{
    commit_message_location, finding_id, git_bytes, git_probe, Carrier, GitObjects, Location,
};
use faculties::schemas::posture::{
    modality, posture, DEFAULT_SCAN_SCOPE_ID, KIND_FINDING, KIND_LEGACY_BRIDGE,
};
use faculties::storage::{load_signer, open_pile_strict};

use crate::descriptor_authority::{
    descriptor_facts, descriptor_handle, materialize_source, retired_root_descriptor,
};

type TextHandle = Inline<Handle<UTF8String>>;

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
    let mut store = open_pile_strict(pile)?;
    let result = plan_open(&mut store, &signer);
    finish_pile(store, result, "Posture bridge planning")
}

/// Write the bridges. Exact replay is idempotent, because both the blobs and
/// the collection record are content addressed.
pub fn publish(
    pile: &Path,
    key: Option<&Path>,
) -> Result<(FindingBridgePlan, Option<CollectionCommit>)> {
    let signer = load_signer(pile, key)?;
    let mut store = open_pile_strict(pile)?;
    let result = (|| {
        let plan = plan_open(&mut store, &signer)?;
        if plan.bridged.is_empty() {
            return Ok((plan, None));
        }

        let descriptor = retired_root_descriptor(DEFAULT_SCAN_SCOPE_ID, signer.verifying_key())?;
        let mut fragment = plan.fragment.clone();
        fragment.describe_with(entity! {
            metadata::description: "posture legacy finding identity bridges".to_owned(),
        });
        let commit = publish_retired_fragment(&mut store, &signer, descriptor, fragment)
            .context("publish Posture finding bridges under the retired descriptor")?;

        let after = plan_open(&mut store, &signer)?;
        if !after.bridged.is_empty() {
            bail!("Posture bridge publication left pending bridge rows");
        }
        Ok((plan, Some(commit)))
    })();
    finish_pile(store, result, "Posture bridge publication")
}

/// Plan against the exact retired Posture descriptor.
///
/// The bridge deliberately runs before descriptor-authority. Publishing it to
/// the current mandatory-authority descriptor would strand it outside the
/// frozen retired leaf set and the subsequent re-seat would not carry it.
fn plan_open(pile: &mut Pile, signer: &SigningKey) -> Result<FindingBridgePlan> {
    let retired = retired_root_descriptor(DEFAULT_SCAN_SCOPE_ID, signer.verifying_key())?;
    let retired_handle = descriptor_handle(&retired);
    let current =
        faculties::collection_names::root_descriptor(DEFAULT_SCAN_SCOPE_ID, signer.verifying_key());
    let current_handle = descriptor_handle(&current);
    let reader = pile
        .snapshot()
        .context("freeze Posture bridge store snapshot")?;
    let discovered = discover_collection_records(&reader)
        .context("discover Posture records for finding bridge")?;

    if discovered.commits().iter().any(|commit| {
        commit.collection() == current_handle
            && commit.public_key().raw == signer.verifying_key().to_bytes()
    }) {
        bail!(
            "Posture already has mandatory-authority COMMITs; the finding bridge must be settled before `migrations descriptor-authority`"
        );
    }

    let source = discovered
        .commits()
        .iter()
        .copied()
        .filter(|commit| commit.collection() == retired_handle)
        .collect::<Vec<_>>();
    if !source.is_empty() {
        let resident =
            descriptor_facts(&reader, retired_handle).context("read retired Posture descriptor")?;
        if resident != *retired.facts() {
            bail!("retired Posture descriptor is not the exact registered epoch");
        }
    }
    let facts =
        materialize_source(&reader, &source).context("materialize retired Posture scan leaves")?;
    build(&facts, &reader)
}

/// Inspect only the frozen retired Posture leaves before descriptor re-seat.
///
/// The caller first checks whether every deterministic successor COMMIT for
/// those leaves is already present. Once that exact epoch boundary exists,
/// replay must not depend on repositories which may since have moved or been
/// collected. Until then this is the authoritative pre-publication audit:
/// bridgeable rows must be settled, while genuinely unrecoverable rows require
/// the descriptor migration's explicit one-shot acceptance.
pub(crate) fn audit_retired_for_descriptor(
    pile: &mut Pile,
    signer: &SigningKey,
) -> Result<FindingBridgePlan> {
    let retired = retired_root_descriptor(DEFAULT_SCAN_SCOPE_ID, signer.verifying_key())?;
    let retired_handle = descriptor_handle(&retired);
    let reader = pile
        .snapshot()
        .context("freeze Posture descriptor-prerequisite store snapshot")?;
    let discovered = discover_collection_records(&reader)
        .context("discover Posture records for descriptor prerequisite")?;
    let retired_source = discovered
        .commits()
        .iter()
        .copied()
        .filter(|commit| commit.collection() == retired_handle)
        .collect::<Vec<_>>();
    if !retired_source.is_empty() {
        let resident =
            descriptor_facts(&reader, retired_handle).context("read retired Posture descriptor")?;
        if resident != *retired.facts() {
            bail!("retired Posture descriptor is not the exact registered epoch");
        }
    }
    let facts = materialize_source(&reader, &retired_source)
        .context("materialize retired Posture facts for descriptor prerequisite")?;
    build(&facts, &reader)
}

/// Publish one fragment under a deliberately retired descriptor.
///
/// The live publication API correctly rejects that descriptor because it has
/// no mandatory authority. This migration-local seam mirrors the normal
/// dependency ordering without weakening the current API: descriptor and
/// fragment attachments, descriptor/data/metadata archives, OFFERs, then the
/// signed COMMIT.
fn publish_retired_fragment(
    pile: &mut Pile,
    signer: &SigningKey,
    descriptor: Fragment,
    fragment: Fragment,
) -> Result<CollectionCommit> {
    let expected = descriptor_handle(&descriptor);
    let (_, descriptor_facts, _, descriptor_blobs) = descriptor.into_parts();
    let (_, facts, metafacts, blobs) = fragment.into_parts();
    let mut capture = OfferCapture::new(pile);

    for blob in sorted_blobs(descriptor_blobs)? {
        capture
            .put::<UnknownBlob, _>(blob)
            .context("store retired Posture descriptor attachment")?;
    }
    let collection = capture
        .put::<SimpleArchive, _>(descriptor_facts)
        .context("store retired Posture descriptor")?;
    if collection != expected {
        bail!("stored retired Posture descriptor changed content identity");
    }
    for blob in sorted_blobs(blobs)? {
        capture
            .put::<UnknownBlob, _>(blob)
            .context("store Posture bridge attachment")?;
    }
    let data = capture
        .put::<SimpleArchive, _>(facts)
        .context("store Posture bridge facts")?;
    let metadata = capture
        .put::<SimpleArchive, _>(metafacts)
        .context("store Posture bridge metadata")?;
    let commit = CollectionCommit::sign(
        signer,
        collection,
        Handle::<SimpleArchive>::to_hash(data),
        metadata,
    );
    capture
        .insert(CollectionRecord::Commit(commit))
        .map_err(|error| anyhow!("append retired Posture bridge COMMIT: {error}"))?;
    Ok(commit)
}

fn sorted_blobs(
    mut blobs: triblespace::core::blob::MemoryBlobStore,
) -> Result<Vec<Blob<UnknownBlob>>> {
    let mut blobs = blobs
        .snapshot()
        .expect("MemoryBlobStore::snapshot is infallible")
        .into_iter()
        .map(|(_, blob)| blob)
        .collect::<Vec<_>>();
    blobs.sort_unstable_by_key(|blob| blob.get_handle().raw);
    Ok(blobs)
}

fn finish_pile<T>(pile: Pile, result: Result<T>, operation: &str) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context(format!("close pile after {operation}"))),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing after {operation} also failed: {close_error}"
        ))),
    }
}

fn build(facts: &TribleSet, reader: &PileSnapshot) -> Result<FindingBridgePlan> {
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
            metadata::tag: &KIND_FINDING,
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
            metadata::tag: &KIND_LEGACY_BRIDGE,
            posture::occurrence: occurrence
        }])) {
            already_bridged += 1;
            continue;
        }
        let locator = read_text(reader, locator, "legacy finding locator")?;
        let value = read_text(reader, value, "legacy finding value")?;
        let modality = find!(
            tag: Id,
            pattern!(facts, [{ finding @ metadata::tag: ?tag }])
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
fn repository_of(facts: &TribleSet, reader: &PileSnapshot, finding: Id) -> Result<Option<PathBuf>> {
    let Some(document) = find!(
        document: Id,
        pattern!(facts, [{ finding @ posture::document: ?document }])
    )
    .next() else {
        return Ok(None);
    };
    let Some(path) = find!(
        path: TextHandle,
        pattern!(facts, [{ document @ posture::path: ?path }])
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
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{sha}^{{commit}}"),
        ],
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

fn read_text(reader: &PileSnapshot, handle: TextHandle, field: &str) -> Result<String> {
    let value: View<str> = reader
        .get(handle)
        .with_context(|| format!("read Posture {field}"))?;
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;
    use faculties::storage::initialize_signer;
    use triblespace::core::collection::CollectionStoreExt;
    use triblespace::core::id::ExclusiveId;

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

    #[test]
    fn descriptor_authority_reseats_the_bridge_leaf_written_to_the_retired_root() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("posture.pile");
        let key_path = directory.path().join("posture.key");
        File::create(&pile_path).unwrap();
        let signer = initialize_signer(&pile_path, Some(&key_path)).unwrap();

        let occurrence = Id::new([0x41; 16]).unwrap();
        let finding = Id::new([0x42; 16]).unwrap();
        let mut legacy = Fragment::empty();
        let locator = legacy.put(
            "rust-attribute-added src/schema.rs#1  \"AAAA\" unsafe as legacy: ShortString;"
                .to_owned(),
        );
        let value = legacy.put("legacy declaration".to_owned());
        legacy += entity! {
            ExclusiveId::force_ref(&finding) @
            metadata::tag: KIND_FINDING,
            metadata::tag: modality::UNSAFE_ATTRIBUTE_ID,
            posture::occurrence: occurrence,
            posture::locator: locator,
            posture::value: value,
        };

        let retired =
            retired_root_descriptor(DEFAULT_SCAN_SCOPE_ID, signer.verifying_key()).unwrap();
        let retired_handle = descriptor_handle(&retired);
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let source = publish_retired_fragment(&mut pile, &signer, retired, legacy).unwrap();
        assert_eq!(source.collection(), retired_handle);

        // A foreign writer can compute the mandatory-authority handle and
        // publish a strictly signed COMMIT on it, but that COMMIT is inert
        // without a resident exact WRITE proof. It may neither fake this occurrence's
        // bridge nor prevent the real retired bridge from being published.
        let foreign = SigningKey::from_bytes(&[0x73; 32]);
        let current_descriptor = faculties::collection_names::root_descriptor(
            DEFAULT_SCAN_SCOPE_ID,
            signer.verifying_key(),
        );
        let current = pile
            .collection::<SimpleArchive>(current_descriptor)
            .unwrap();
        let current_handle = current.handle();
        let fake_bridge = entity! {
            metadata::tag: KIND_LEGACY_BRIDGE,
            posture::occurrence: occurrence,
            posture::sighting_of: Id::new([0x55; 16]).unwrap(),
        };
        pile.commit(current, &foreign, fake_bridge).unwrap();
        pile.close().unwrap();

        let error = crate::descriptor_authority::publish_path(&pile_path, Some(&key_path))
            .expect_err("descriptor-first must not strand a bridgeable finding");
        assert!(error.to_string().contains("bridgeable legacy Posture"));
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        let records = discover_collection_records(&snapshot).unwrap();
        assert_eq!(records.commits().len(), 2);
        assert_eq!(
            records
                .commits()
                .iter()
                .filter(|commit| commit.collection() == retired_handle)
                .count(),
            1
        );
        assert_eq!(
            records
                .commits()
                .iter()
                .filter(|commit| commit.collection() == current_handle)
                .count(),
            1
        );
        pile.close().unwrap();

        let (planned, bridge) = publish(&pile_path, Some(&key_path)).unwrap();
        assert_eq!(planned.bridged().len(), 1);
        let bridge = bridge.expect("one bridge COMMIT");
        assert_eq!(bridge.collection(), retired_handle);

        let report = crate::descriptor_authority::publish_path(&pile_path, Some(&key_path))
            .expect("re-seat retired Posture leaves");
        let root = report
            .plan
            .roots
            .iter()
            .find(|root| root.scope == DEFAULT_SCAN_SCOPE_ID)
            .expect("Posture root was planned");
        assert_eq!(root.source_commits, 2);
        assert_eq!(root.target_commits, 2);
        assert_eq!(root.missing_commits, 0);

        let expected_bridge =
            CollectionCommit::sign(&signer, root.new, bridge.data(), bridge.metadata());
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        let records = discover_collection_records(&snapshot).unwrap();
        assert!(records
            .commits()
            .iter()
            .any(|commit| commit.id() == expected_bridge.id()));
        pile.close().unwrap();
    }

    #[test]
    fn unrecoverable_findings_require_one_explicit_epoch_acceptance() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("posture.pile");
        let key_path = directory.path().join("posture.key");
        File::create(&pile_path).unwrap();
        let signer = initialize_signer(&pile_path, Some(&key_path)).unwrap();

        let occurrence = Id::new([0x61; 16]).unwrap();
        let finding = Id::new([0x62; 16]).unwrap();
        let mut legacy = Fragment::empty();
        let locator = legacy.put("docProps/core.xml creator".to_owned());
        let value = legacy.put("legacy author".to_owned());
        legacy += entity! {
            ExclusiveId::force_ref(&finding) @
            metadata::tag: KIND_FINDING,
            metadata::tag: modality::OOXML_CORE_PROPS,
            posture::occurrence: occurrence,
            posture::locator: locator,
            posture::value: value,
        };

        let retired =
            retired_root_descriptor(DEFAULT_SCAN_SCOPE_ID, signer.verifying_key()).unwrap();
        let mut pile = open_pile_strict(&pile_path).unwrap();
        publish_retired_fragment(&mut pile, &signer, retired, legacy).unwrap();
        pile.close().unwrap();

        let plan = crate::descriptor_authority::plan_path(&pile_path, Some(&key_path)).unwrap();
        assert_eq!(plan.posture_pending_bridges, 0);
        assert_eq!(plan.posture_unbridged, 1);
        assert!(!plan.posture_reseat_complete);
        let before = std::fs::read(&pile_path).unwrap();
        let error = crate::descriptor_authority::publish_path(&pile_path, Some(&key_path))
            .expect_err("unrecoverable Posture rows need explicit acceptance");
        assert!(error.to_string().contains("--accept-unbridged-posture"));
        assert_eq!(std::fs::read(&pile_path).unwrap(), before);

        let accepted = crate::descriptor_authority::publish_path_with_options(
            &pile_path,
            Some(&key_path),
            crate::descriptor_authority::DescriptorAuthorityOptions {
                accept_unbridged_posture: true,
            },
        )
        .unwrap();
        assert!(accepted.plan.posture_reseat_complete);
        assert_eq!(accepted.plan.posture_unbridged, 0);

        // Exact deterministic target leaves embody the one-shot acceptance;
        // replay does not consult the old environment or need the flag again.
        let replay =
            crate::descriptor_authority::publish_path(&pile_path, Some(&key_path)).unwrap();
        assert_eq!(replay.appended_commits, 0);
        assert!(replay.plan.posture_reseat_complete);
    }
}
