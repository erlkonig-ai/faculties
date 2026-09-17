//! The properties the Code catalogue is only correct if it has.
//!
//! IDEMPOTENCE (an unchanged tree re-ingests to nothing), CONVERGENCE (two
//! machines ingesting the same tree produce one catalogue under `cat`), and the
//! acceptance questions themselves, answered over a fixture repository.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use faculties::code::operations::{Code, Filter, IngestOptions, Revision};
use faculties::out::{Out, Part};
use faculties::storage::initialize_signer;

struct Fixture {
    _directory: tempfile::TempDir,
    repo: PathBuf,
    pile: PathBuf,
    key: PathBuf,
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?} failed");
}

/// Two files with one byte-identical function between them, one documented
/// kernel, one unparseable file, and one prose file.
const MESH: &str = r#"//! Mesh helpers for the lattice widget.

/// Points along an arc.
pub fn arc_points(n: u8) -> u8 {
    n + 1
}
"#;

const LATTICE: &str = r#"//! Lattice layout.
use cubecl::wgpu::WgpuRuntime;

// ── GPU force-directed layout kernel ──
/// One integration step of the force-directed layout, on GPU.
pub fn force_step_kernel(n: u8) -> u8 {
    n
}

/// Points along an arc.
pub fn arc_points(n: u8) -> u8 {
    n + 1
}

/// Minimum linear arrangement by simulated annealing.
pub fn anneal_minla(n: u8) -> u8 {
    n
}
"#;

const BROKEN: &str = "//! Still prose, even unparsed.\nfn broken( {\n";

const README: &str = "# Fixture\n\nA fixture repository for the code catalogue.\n";

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let repo = directory.path().join("gorbie-fixture");
        fs::create_dir_all(repo.join("src")).unwrap();
        fs::write(repo.join("src/mesh.rs"), MESH).unwrap();
        fs::write(repo.join("src/lattice.rs"), LATTICE).unwrap();
        fs::write(repo.join("src/broken.rs"), BROKEN).unwrap();
        fs::write(repo.join("README.md"), README).unwrap();
        git(&repo, &["init", "--quiet"]);
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "--quiet", "-m", "fixture"]);

        let pile = directory.path().join("code.pile");
        let key = directory.path().join("code.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();

        Self {
            _directory: directory,
            repo,
            pile,
            key,
        }
    }

    fn code(&self) -> Code {
        Code::new(self.pile.clone(), Some(self.key.clone()))
    }

    fn ingest(&self) {
        self.code()
            .ingest(&[self.repo.clone()], &IngestOptions::default())
            .expect("ingest the fixture repository");
    }

    fn pile_len(&self) -> u64 {
        fs::metadata(&self.pile).unwrap().len()
    }
}

fn collect(render: impl FnOnce(&mut Out<'_>) -> anyhow::Result<()>) -> String {
    let mut text = String::new();
    let mut emit = |part: Part| {
        if let Part::Text { text: part } = part {
            text.push_str(&part);
        }
        Ok(())
    };
    render(&mut Out::new(&mut emit)).unwrap();
    text
}

#[test]
fn re_ingesting_an_unchanged_tree_writes_nothing() {
    let fixture = Fixture::new();
    fixture.ingest();
    // One read, to settle the accelerated fact cover for what the ingest just
    // published. An ingest publishes its COMMIT after opening, so the cover it
    // maintained on the way in is one commit behind when it closes, and the
    // next process to open the pile flushes that. That flush is index
    // maintenance, not new facts — and measuring "writes nothing" while it is
    // still outstanding would measure the previous run, not this one.
    fixture.code().stats(&Filter::default()).unwrap();
    let after_first = fixture.pile_len();

    fixture.ingest();

    // The unit fast path: same repo, same path, same bytes, so not one file is
    // re-parsed, not one fact is new, and not one byte is written.
    assert_eq!(
        after_first,
        fixture.pile_len(),
        "a second ingest of an unchanged tree grew the pile"
    );
}

#[test]
fn two_independent_ingests_of_one_tree_produce_the_same_entities() {
    let left = Fixture::new();
    left.ingest();

    // A second machine, with its own pile and its own signer, cataloguing the
    // same tree.
    let second = tempfile::tempdir().unwrap();
    let pile = second.path().join("other.pile");
    let key = second.path().join("other.key");
    fs::File::create(&pile).unwrap();
    initialize_signer(&pile, Some(&key)).unwrap();
    let right = Code::new(pile.clone(), Some(key.clone()));
    right
        .ingest(&[left.repo.clone()], &IngestOptions::default())
        .unwrap();

    // THE convergence property: identity is content, so two machines that
    // never spoke agree on the item id without coordinating. Nothing
    // machine-local — absolute path, wall clock, iteration order, signing key —
    // reaches a core.
    let here = left
        .code()
        .find("force_step_kernel", &Filter::default())
        .unwrap();
    let there = right.find("force_step_kernel", &Filter::default()).unwrap();
    assert_eq!(here.hits.len(), 1);
    assert_eq!(there.hits.len(), 1);
    assert_eq!(here.hits[0].item, there.hits[0].item);
    assert_eq!(
        here.provenance.scans[0].commit,
        there.provenance.scans[0].commit
    );

    // Concatenation is the merge, and it neither duplicates nor damages
    // anything. It does NOT make the second machine's facts visible here: each
    // faculty collection is signer-private, so the other pile's COMMITs are not
    // admitted by this one's WRITE policy. Sharing is a descriptor decision,
    // not a side effect of `cat`.
    let before = left
        .code()
        .stats(&Filter::default())
        .unwrap()
        .rows
        .into_iter()
        .map(|row| (row.units, row.placements))
        .collect::<Vec<_>>();

    let mut destination = fs::OpenOptions::new()
        .append(true)
        .open(&left.pile)
        .unwrap();
    let mut source = fs::File::open(&pile).unwrap();
    std::io::copy(&mut source, &mut destination).unwrap();
    drop(destination);

    let after = left
        .code()
        .stats(&Filter::default())
        .unwrap()
        .rows
        .into_iter()
        .map(|row| (row.units, row.placements))
        .collect::<Vec<_>>();
    assert_eq!(before, after, "concatenation changed the catalogue");
}

#[test]
fn a_definition_is_found_and_an_absence_is_stated_with_its_denominator() {
    let fixture = Fixture::new();
    fixture.ingest();
    let code = fixture.code();

    let found = code.find("force_step_kernel", &Filter::default()).unwrap();
    assert_eq!(found.hits.len(), 1, "{found:?}");
    assert!(found.hits[0].path.ends_with("lattice.rs"));
    assert_eq!(found.hits[0].line, 6);

    let absent = code.find("LearnerBuilder", &Filter::default()).unwrap();
    assert!(absent.hits.is_empty());
    let rendered = collect(|out| faculties::code::render::definition(&absent, out));
    assert!(rendered.contains("ABSENT"), "{rendered}");
    assert!(rendered.contains("unit(s)"), "{rendered}");
    assert!(rendered.contains("searched"), "{rendered}");
}

#[test]
fn an_unresolved_usage_question_is_answered_exactly_for_a_rare_identifier() {
    let fixture = Fixture::new();
    fixture.ingest();
    let code = fixture.code();

    // The joined path, not just its segments.
    let hits = code.uses("cubecl::wgpu", &Filter::default()).unwrap();
    assert!(!hits.hits.is_empty(), "{hits:?}");

    let none = code.uses("burn::train", &Filter::default()).unwrap();
    assert!(none.hits.is_empty(), "{none:?}");

    let (imports, _) = code.imports("cubecl", &Filter::default()).unwrap();
    assert_eq!(imports, 1);
}

#[test]
fn byte_identical_code_in_two_files_is_one_item_with_two_placements() {
    let fixture = Fixture::new();
    fixture.ingest();
    let report = fixture
        .code()
        .duplicates(1, false, &Filter::default())
        .unwrap();
    let names: Vec<String> = report
        .groups
        .iter()
        .filter_map(|group| group.name.clone())
        .collect();
    assert!(names.contains(&"arc_points".to_owned()), "{names:?}");
    let group = report
        .groups
        .iter()
        .find(|group| group.name.as_deref() == Some("arc_points"))
        .unwrap();
    assert_eq!(group.places.len(), 2);
}

#[test]
fn an_unparseable_file_is_catalogued_rather_than_refused() {
    let fixture = Fixture::new();
    fixture.ingest();
    let stats = fixture.code().stats(&Filter::default()).unwrap();
    let row = stats.rows.first().expect("one repository");
    assert_eq!(row.parse_failures, 1, "{row:?}");
    // The unit is still counted, so the gap is visible instead of silent.
    assert_eq!(row.units, 4);
}

#[test]
fn a_dirty_tree_is_a_different_revision_from_its_head() {
    let fixture = Fixture::new();
    fixture.ingest();
    let head = fixture.code().stats(&Filter::default()).unwrap();
    let head_label = head.rows[0].scan.clone();
    assert!(!head_label.ends_with("@worktree"), "{head_label}");

    fs::write(
        fixture.repo.join("src/mesh.rs"),
        format!("{MESH}\n/// added\npub fn added() {{}}\n"),
    )
    .unwrap();
    fixture.ingest();

    let worktree = fixture
        .code()
        .stats(&Filter {
            revision: Revision::Worktree,
            ..Filter::default()
        })
        .unwrap();
    assert_eq!(worktree.rows.len(), 1);
    assert!(worktree.rows[0].scan.ends_with("@worktree"));

    // The same question, answered at two revisions, gives two answers — which
    // is the whole point of carrying the revision in the answer.
    let at_head = fixture
        .code()
        .find(
            "added",
            &Filter {
                revision: Revision::Selector(format!(
                    "gorbie-fixture@{}",
                    head_label.split('@').nth(1).unwrap()
                )),
                ..Filter::default()
            },
        )
        .unwrap();
    assert!(at_head.hits.is_empty(), "{at_head:?}");

    let at_worktree = fixture
        .code()
        .find(
            "added",
            &Filter {
                revision: Revision::Worktree,
                ..Filter::default()
            },
        )
        .unwrap();
    assert_eq!(at_worktree.hits.len(), 1, "{at_worktree:?}");
}

#[test]
fn a_named_revision_can_be_ingested_from_git_objects() {
    let fixture = Fixture::new();
    let head = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(&fixture.repo)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();

    fixture
        .code()
        .ingest(
            &[fixture.repo.clone()],
            &IngestOptions {
                commit: Some(head.clone()),
                dry_run: false,
            },
        )
        .unwrap();

    let stats = fixture
        .code()
        .stats(&Filter {
            revision: Revision::Selector(head[..8].to_owned()),
            ..Filter::default()
        })
        .unwrap();
    assert_eq!(stats.rows.len(), 1);
    assert_eq!(stats.rows[0].units, 4);
}

#[test]
fn history_is_asked_of_git_rather_than_inferred_from_a_name_set() {
    let fixture = Fixture::new();
    let report = fixture
        .code()
        .blame("arc_points", &[fixture.repo.clone()], 5)
        .unwrap();
    assert_eq!(report.rows.len(), 1, "{report:?}");
    assert_eq!(report.rows[0].subject, "fixture");
    assert!(report.rows[0]
        .paths
        .iter()
        .any(|path| path.ends_with("mesh.rs")));
}

#[test]
fn the_capability_question_ranks_the_file_that_holds_the_kernel() {
    let fixture = Fixture::new();
    fixture.ingest();
    fixture.code().index().expect("build the lexical covers");

    let report = fixture
        .code()
        .search(
            "gpu force directed graph layout",
            faculties::code::index::Tier::Both,
            5,
            &Filter::default(),
        )
        .unwrap();
    assert!(report.stale.is_none(), "{:?}", report.stale);
    let top = report.groups.first().expect("at least one group");
    assert!(top.path.ends_with("lattice.rs"), "{report:?}");
    // The evidence line is derived rarity, not a vocabulary of "GPU things".
    assert!(
        top.distinguishing.contains(&"cubecl".to_owned()),
        "{:?}",
        top.distinguishing
    );
}
