//! How a Posture finding is identified: by CONTENT, not by where a commit
//! happened to put it.
//!
//! This is shared vocabulary rather than tool-internal detail, because the
//! findings migration has to derive exactly the same ids the scanner does —
//! that is the whole point of bridging a pre-2026-08-18 occurrence onto the
//! finding it turned out to be.
//!
//! A finding's id is `(modality, carrier, inner locator)`. It used to be
//! `(modality, path, commit:path:line, value)`, and commit surgery destroyed
//! that: a rebase, cherry-pick, amend or history scrub gives the same material
//! a new `commit:path:line`, hence a new id, so every Decide resolution
//! silently stopped applying and the finding re-blocked.
//!
//! The coordinate is MODALITY-DEPENDENT on purpose. Source material has a git
//! blob and blobs survive commit surgery byte-identical; a byte range into an
//! OOXML zip or a PDF means nothing, so a container's carrier is the member
//! posture extracted, hashed by posture; and a commit message has no blob at
//! all, so its carrier is the commit.

use std::path::Path;
use std::rc::Rc;

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use triblespace::core::id::Id;
use triblespace::core::metadata;
use triblespace::core::trible::Fragment;
use triblespace::macros::entity;
use triblespace::prelude::*;

use crate::schemas::posture::{
    posture, CARRIER_CONTAINER_MEMBER, CARRIER_GIT_BLOB, CARRIER_GIT_COMMIT, KIND_FINDING,
};

type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;

/// The content-addressed unit a finding's material sits in.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Carrier {
    /// A git blob, by object id. Commit surgery rewrites commits while
    /// producing byte-identical blobs, so this is stable across exactly the
    /// operations that broke the old locator.
    GitBlob(String),
    /// Bytes posture pulled out of a container — an OOXML part, a PDF page
    /// content stream, an EXIF/TIFF block — addressed by posture's own BLAKE3
    /// hash of those exact bytes.
    ///
    /// The honest cost: `git blame -M -C` can carry a blob finding forward
    /// across a rename or an unrelated edit, and it cannot do that here. A
    /// container finding survives only as long as the extracted member's bytes
    /// do.
    Member(String),
    /// A commit. A commit message has no blob, so this is the one carrier
    /// commit surgery still moves: a rebased message is a new finding, and
    /// there is nothing content-addressed to hold it still.
    Commit(String),
}

impl Carrier {
    /// Hash exactly the bytes posture extracted from a container.
    pub fn member(bytes: &[u8]) -> Self {
        Self::Member(blake3::hash(bytes).to_hex().to_string())
    }

    pub fn kind(&self) -> Id {
        match self {
            Self::GitBlob(_) => CARRIER_GIT_BLOB,
            Self::Member(_) => CARRIER_CONTAINER_MEMBER,
            Self::Commit(_) => CARRIER_GIT_COMMIT,
        }
    }

    pub fn address(&self) -> &str {
        match self {
            Self::GitBlob(address) | Self::Member(address) | Self::Commit(address) => address,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::GitBlob(_) => "blob",
            Self::Member(_) => "member",
            Self::Commit(_) => "commit",
        }
    }

    /// Display only. Identity always uses the complete address.
    pub fn short(&self) -> &str {
        let address = self.address();
        &address[..address.len().min(8)]
    }
}

/// Where inside the carrier the material is.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Inner {
    /// Byte range `[start, end)` — used exactly where the carrier's bytes
    /// literally spell the material, which is what makes the content
    /// *derivable* instead of identifying. The span is the material, not its
    /// containing line.
    Span { start: u64, end: u64 },
    /// A named coordinate, for material a carrier's bytes do not literally
    /// spell: a decoded EXIF tag, an XML-escaped OOXML property, text
    /// reconstructed from PDF glyphs, or the path a blob is stored under. The
    /// carrier's hash still covers the content, so a changed value at the same
    /// coordinate is a different finding.
    Field(String),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Location {
    pub carrier: Carrier,
    pub inner: Inner,
}

impl Location {
    pub fn span(carrier: Carrier, start: u64, end: u64) -> Self {
        Self {
            carrier,
            inner: Inner::Span { start, end },
        }
    }

    pub fn field(carrier: Carrier, field: impl Into<String>) -> Self {
        Self {
            carrier,
            inner: Inner::Field(field.into()),
        }
    }

    pub fn display(&self) -> String {
        match &self.inner {
            Inner::Span { start, end } => format!(
                "{} {}@{start}-{end}",
                self.carrier.label(),
                self.carrier.short()
            ),
            Inner::Field(field) => {
                format!("{} {} {field}", self.carrier.label(), self.carrier.short())
            }
        }
    }
}

/// Write one finding and return its identity: modality, the content-addressed
/// carrier, and the inner locator — nothing else. No path, no commit, no line,
/// and deliberately not the value: a byte range in a content-addressed carrier
/// IS the bytes, so recording the material in the id would only let the two
/// disagree, and for a carrier posture hashed itself the hash already covers a
/// changed value.
pub fn finding_entity(fragment: &mut Fragment, modality: Id, location: &Location) -> Id {
    let (facts, id) = finding_fragment(modality, location);
    *fragment += facts;
    id
}

/// The id [`finding_entity`] would write, without writing anything.
pub fn finding_id(modality: Id, location: &Location) -> Id {
    finding_fragment(modality, location).1
}

fn finding_fragment(modality: Id, location: &Location) -> (Fragment, Id) {
    let mut fragment = Fragment::empty();
    let carrier: TextHandle = fragment.put(location.carrier.address().to_owned());
    let field: Option<TextHandle> = match &location.inner {
        Inner::Field(field) => Some(fragment.put(field.clone())),
        Inner::Span { .. } => None,
    };
    let (start, end) = match &location.inner {
        Inner::Span { start, end } => (Some(*start), Some(*end)),
        Inner::Field(_) => (None, None),
    };
    let finding = entity! {
        metadata::tag: KIND_FINDING,
        metadata::tag: modality,
        posture::carrier_kind: location.carrier.kind(),
        posture::carrier: carrier,
        posture::locator?: field,
        posture::span_start?: start,
        posture::span_end?: end,
    };
    let id = finding
        .root()
        .expect("content-located finding has one intrinsic root");
    fragment += finding;
    (fragment, id)
}


// ── the git side of locating source material ────────────────────────────────
//
// Shared with the findings migration on purpose: a bridged legacy occurrence
// has to name exactly the id a re-scan derives, and two implementations of
// "where does this line live" would drift the day one of them was fixed.

/// Raw bytes of a git subprocess. A blob is not text, and a byte offset into a
/// lossily decoded copy addresses the wrong material.
pub fn git_bytes(repo_root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = std::process::Command::new("git")
        .env("LC_ALL", "C")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .with_context(|| format!("run git -C {} {}", repo_root.display(), args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        bail!(
            "git -C {} {} failed{}",
            repo_root.display(),
            args.join(" "),
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        );
    }
    Ok(output.stdout)
}

/// Byte offset of the first case-insensitive ASCII match, on the ORIGINAL
/// bytes. Lowercasing first would be simpler and wrong: `to_lowercase` can
/// change a string's length, and then every offset after the first non-ASCII
/// character addresses different material.
pub fn find_ascii_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|start| {
        haystack[*start..*start + needle.len()]
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

/// Byte range of the 1-based `line` in `bytes`, excluding its newline.
pub fn line_range(bytes: &[u8], line: u64) -> Option<(u64, u64)> {
    let mut start = 0usize;
    let mut current = 1u64;
    while current < line {
        start = bytes[start..].iter().position(|byte| *byte == b'\n')? + start + 1;
        current += 1;
    }
    if start > bytes.len() {
        return None;
    }
    let end = bytes[start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|offset| start + offset)
        .unwrap_or(bytes.len());
    Some((start as u64, end as u64))
}

/// Where git says the material on a line was introduced.
///
/// `git blame -M -C` is the judgement posture deliberately does not make for
/// itself: git already decides "did this move or is it new" on evidence, for
/// `blame`, including across renames and copies. Failing to blame (a path the
/// commit does not have, a repository without the object) is not an audit
/// failure — it only means there is no earlier anchor than the sighting.
pub fn blame_origin(
    repo_root: &Path,
    commit: &str,
    path: &str,
    line: u64,
) -> Option<(String, String, u64)> {
    let range = format!("{line},{line}");
    let porcelain = git_bytes(
        repo_root,
        &["blame", "--porcelain", "-M", "-C", "-L", &range, commit, "--", path],
    )
    .ok()?;
    let porcelain = String::from_utf8_lossy(&porcelain);
    let mut lines = porcelain.lines();
    let mut header = lines.next()?.split_whitespace();
    let origin_commit = header.next()?.to_owned();
    let origin_line = header.next()?.parse::<u64>().ok()?;
    let origin_path = lines
        .find_map(|line| line.strip_prefix("filename "))
        .unwrap_or(path)
        .to_owned();
    Some((origin_commit, origin_path, origin_line))
}

/// Memoized git object reads. An audit asks for the same blob once per hit in
/// it, and `cat-file` is a process each time.
#[derive(Default)]
pub struct GitObjects {
    blobs: BTreeMap<String, Rc<Vec<u8>>>,
    paths: BTreeMap<(String, String), Option<String>>,
}

impl GitObjects {
    /// Object id of `path` at `treeish`, or `None` when that tree has no such
    /// path (the commit deleted it, or it was never there).
    pub fn blob_at(&mut self, repo_root: &Path, treeish: &str, path: &str) -> Result<Option<String>> {
        let key = (treeish.to_owned(), path.to_owned());
        if let Some(found) = self.paths.get(&key) {
            return Ok(found.clone());
        }
        let object = format!("{treeish}:{path}");
        let found = git_probe(repo_root, &["rev-parse", "--verify", "--quiet", &object], &[1])?
            .map(|id| id.trim().to_owned())
            .filter(|id| !id.is_empty());
        self.paths.insert(key, found.clone());
        Ok(found)
    }

    pub fn bytes(&mut self, repo_root: &Path, oid: &str) -> Result<Rc<Vec<u8>>> {
        if let Some(bytes) = self.blobs.get(oid) {
            return Ok(bytes.clone());
        }
        let bytes = Rc::new(git_bytes(repo_root, &["cat-file", "blob", oid])?);
        self.blobs.insert(oid.to_owned(), bytes.clone());
        Ok(bytes)
    }

    /// The content-located site of `needle` on one line of a source file,
    /// carried back to the blob git says introduced the material.
    ///
    /// This is the carry-forward the whole redesign turns on. Editing line 400
    /// of a file gives it a new blob, so a finding at line 12 would look new
    /// every time the file changed anywhere; asking blame first anchors it to
    /// the blob the line was actually introduced in, which a later edit does
    /// not touch. A rebase needs no help at all — it produces byte-identical
    /// blobs, so the id never moved in the first place.
    pub fn locate(
        &mut self,
        repo_root: &Path,
        commit: &str,
        path: &str,
        line: u64,
        needle: &str,
    ) -> Result<Location> {
        let mut candidates = Vec::new();
        if let Some(origin) = blame_origin(repo_root, commit, path, line) {
            candidates.push(origin);
        }
        candidates.push((commit.to_owned(), path.to_owned(), line));
        for (at_commit, at_path, at_line) in candidates {
            let Some(oid) = self.blob_at(repo_root, &at_commit, &at_path)? else {
                continue;
            };
            let bytes = self.bytes(repo_root, &oid)?;
            let Some((start, end)) = line_range(&bytes, at_line) else {
                continue;
            };
            let Some(offset) = find_ascii_ci(&bytes[start as usize..end as usize], needle.as_bytes())
            else {
                continue;
            };
            let start = start + offset as u64;
            return Ok(Location::span(
                Carrier::GitBlob(oid),
                start,
                start + needle.len() as u64,
            ));
        }
        // No blob spells it — a non-ASCII term, or material only the patch
        // carries. The honest carrier is then the commit that published it,
        // and commit surgery does move that.
        Ok(Location::field(
            Carrier::Commit(commit.to_owned()),
            format!("{path}:{line}"),
        ))
    }
}



/// Run git where a nonzero status can be an ordinary answer ("no such
/// object", "no origin remote") rather than a failure.
pub fn git_probe(repo_path: &Path, args: &[&str], absent_statuses: &[i32]) -> Result<Option<String>> {
    let output = std::process::Command::new("git")
        .env("LC_ALL", "C")
        .arg("-C")
        .arg(repo_path)
        .args(args)
        .output()
        .with_context(|| format!("run git -C {} {}", repo_path.display(), args.join(" ")))?;
    if output.status.success() {
        return Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        ));
    }
    if output
        .status
        .code()
        .is_some_and(|code| absent_statuses.contains(&code))
    {
        return Ok(None);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    bail!(
        "git -C {} {} failed{}",
        repo_path.display(),
        args.join(" "),
        if stderr.is_empty() {
            String::new()
        } else {
            format!(": {stderr}")
        }
    )
}


/// Where a protected term sits inside a commit message.
///
/// A commit message has no blob, so the carrier is the commit itself — the one
/// coordinate commit surgery still moves, and the honest place to say so. The
/// scanner and the findings migration both call this so a bridged id is the
/// same id a re-scan derives.
pub fn commit_message_location(sha: &str, offset: usize, line: &str, line_index: usize, needle: &str) -> Location {
    match find_ascii_ci(line.as_bytes(), needle.as_bytes()) {
        Some(at) => {
            let start = (offset + at) as u64;
            Location::span(
                Carrier::Commit(sha.to_owned()),
                start,
                start + needle.len() as u64,
            )
        }
        // A non-ASCII term the byte search cannot address. The line is still
        // the honest coordinate; the span would have been a guess.
        None => Location::field(
            Carrier::Commit(sha.to_owned()),
            format!("message:{}", line_index + 1),
        ),
    }
}
