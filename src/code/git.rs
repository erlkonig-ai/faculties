//! Git as the walker.
//!
//! Ignore rules, submodules, `target*` directories and the tracked/untracked
//! split are all things git already knows, so this module asks it rather than
//! re-deriving them from a filesystem walk and an ignore list that would drift.
//! `posture` already shells out to `git` exactly this way; no `git2`/`gix`
//! dependency is added for it.
//!
//! Nothing here stores a git sha as an identity. The pile is Blake3-fixed and
//! computes a blob's real content id when it is inserted; a commit string is
//! provenance on a scan, never a key.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

/// One blob named by a tree listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeEntry {
    pub path: String,
    pub object: String,
}

/// One commit a pickaxe search found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Change {
    pub commit: String,
    pub date: String,
    pub subject: String,
}

fn git(dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("run git {} in {}", args.join(" "), dir.display()))?;
    if !output.status.success() {
        bail!(
            "git {} in {} failed: {}",
            args.join(" "),
            dir.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn git_text(dir: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8_lossy(&git(dir, args)?).trim().to_owned())
}

/// Whether `dir` is the root of a git working copy.
pub fn is_repository(dir: &Path) -> bool {
    dir.join(".git").exists()
}

/// The revision a repository's HEAD currently names.
pub fn head(dir: &Path) -> Result<String> {
    git_text(dir, &["rev-parse", "HEAD"])
}

/// Resolve a revision the caller spelled loosely, e.g. an abbreviated sha.
pub fn resolve(dir: &Path, revision: &str) -> Result<String> {
    git_text(
        dir,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{revision}^{{commit}}"),
        ],
    )
}

/// Whether the working tree differs from HEAD in any tracked file.
pub fn is_dirty(dir: &Path) -> Result<bool> {
    Ok(!git_text(dir, &["status", "--porcelain", "--untracked-files=no"])?.is_empty())
}

/// Every tracked path in the working tree.
///
/// Deliberately unfiltered. Git decides what is tracked — which is where ignore
/// rules, submodules and `target*` come from — and the LANGUAGE table decides
/// what this build can model. Two filters would be two places to drift, and
/// `ls-tree` does not honour glob pathspecs the way `ls-files` does, so a
/// shared pattern list would have silently returned nothing at a named
/// revision while working perfectly in the working tree.
pub fn ls_files(dir: &Path) -> Result<Vec<String>> {
    let raw = git(dir, &["ls-files", "-z"])?;
    Ok(split_nul(&raw))
}

/// Every path and blob object at one revision.
pub fn ls_tree(dir: &Path, commit: &str) -> Result<Vec<TreeEntry>> {
    let raw = git(dir, &["ls-tree", "-r", "-z", commit])?;
    let mut entries = Vec::new();
    for record in split_nul(&raw) {
        // `<mode> SP <type> SP <object> TAB <path>`
        let Some((meta, path)) = record.split_once('\t') else {
            continue;
        };
        let fields: Vec<&str> = meta.split_whitespace().collect();
        if fields.len() < 3 || fields[1] != "blob" {
            continue;
        }
        entries.push(TreeEntry {
            path: path.to_owned(),
            object: fields[2].to_owned(),
        });
    }
    Ok(entries)
}

/// Stream the contents of many objects through one `git cat-file --batch`.
///
/// One process for a whole tree rather than one per file; the caller sees each
/// payload once and decides whether to keep it.
pub fn cat_objects(
    dir: &Path,
    objects: &[String],
    mut receive: impl FnMut(&str, Vec<u8>) -> Result<()>,
) -> Result<()> {
    if objects.is_empty() {
        return Ok(());
    }
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn git cat-file --batch in {}", dir.display()))?;

    let mut stdin = child.stdin.take().context("git cat-file stdin")?;
    let requested: Vec<String> = objects.to_vec();
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        for object in &requested {
            stdin.write_all(object.as_bytes())?;
            stdin.write_all(b"\n")?;
        }
        stdin.flush()
    });

    let mut stdout = BufReader::new(child.stdout.take().context("git cat-file stdout")?);
    let mut header = String::new();
    for _ in 0..objects.len() {
        header.clear();
        if stdout.read_line(&mut header)? == 0 {
            break;
        }
        let fields: Vec<&str> = header.split_whitespace().collect();
        if fields.len() < 3 {
            // `<object> SP missing` — an object this checkout does not hold is
            // skipped, not an error.
            continue;
        }
        let object = fields[0].to_owned();
        let size: usize = fields[2]
            .parse()
            .with_context(|| format!("git cat-file size for {object}"))?;
        let mut payload = vec![0_u8; size];
        stdout.read_exact(&mut payload)?;
        let mut newline = [0_u8; 1];
        stdout.read_exact(&mut newline)?;
        receive(&object, payload)?;
    }
    drop(stdout);
    let _ = writer.join();
    let status = child.wait().context("wait for git cat-file --batch")?;
    if !status.success() {
        bail!("git cat-file --batch in {} failed", dir.display());
    }
    Ok(())
}

/// Commits whose diff adds or removes an occurrence of `identifier`.
///
/// This is the deliberate seam between the catalogue and history: the pile
/// answers from facts when it holds them and asks git when it does not. Git
/// shows the DIFF, so unlike a name-set difference between two scans it cannot
/// misread a rename-with-edit as a removal.
pub fn pickaxe(dir: &Path, identifier: &str, limit: usize) -> Result<Vec<Change>> {
    let limit = limit.to_string();
    let output = git(
        dir,
        &[
            "log",
            "-S",
            identifier,
            "--max-count",
            &limit,
            "--date=short",
            "--pretty=format:%H%x1f%ad%x1f%s",
        ],
    )?;
    let text = String::from_utf8_lossy(&output);
    let mut changes = Vec::new();
    for line in text.lines() {
        let mut fields = line.split('\u{1f}');
        let (Some(commit), Some(date), Some(subject)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        changes.push(Change {
            commit: commit.to_owned(),
            date: date.to_owned(),
            subject: subject.to_owned(),
        });
    }
    Ok(changes)
}

/// The paths one commit touched, for explaining a pickaxe hit.
pub fn commit_paths(dir: &Path, commit: &str, limit: usize) -> Result<Vec<String>> {
    let text = git_text(dir, &["show", "--name-only", "--pretty=format:", commit])?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(limit)
        .map(ToOwned::to_owned)
        .collect())
}

fn split_nul(raw: &[u8]) -> Vec<String> {
    raw.split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .map(|record| String::from_utf8_lossy(record).into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tree_listing_keeps_only_blobs() {
        let raw = b"100644 blob abc123\tsrc/lib.rs\0040000 tree def456\tsrc\0".to_vec();
        let mut entries = Vec::new();
        for record in split_nul(&raw) {
            let Some((meta, path)) = record.split_once('\t') else {
                continue;
            };
            let fields: Vec<&str> = meta.split_whitespace().collect();
            if fields.len() < 3 || fields[1] != "blob" {
                continue;
            }
            entries.push((path.to_owned(), fields[2].to_owned()));
        }
        assert_eq!(
            entries,
            vec![("src/lib.rs".to_owned(), "abc123".to_owned())]
        );
    }

    #[test]
    fn nul_separated_output_drops_the_trailing_empty_record() {
        assert_eq!(split_nul(b"a\0b\0"), vec!["a".to_owned(), "b".to_owned()]);
    }
}
