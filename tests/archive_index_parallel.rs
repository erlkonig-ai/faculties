//! End-to-end invariants for the standalone archive leaf-preparation pipeline.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use faculties::schemas::archive::archive;
use triblespace::core::blob::encodings::succinctarchive::{
    SuccinctArchiveBlob, SuccinctArchiveRank9IndexBlob,
};
use triblespace::core::blob::Blob;
use triblespace::core::repo::index_home::{Manifest, SuccinctRollup};
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{BlobStore, PinStore, Repository, Workspace};
use triblespace::prelude::blobencodings::{LongString, SimpleArchive};
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;
use triblespace_search::index_bm25::Bm25Rollup;
use triblespace_search::succinct::SuccinctBM25Blob;

type CommitHandle = Inline<Handle<SimpleArchive>>;

fn temp_pile_path(label: &str) -> PathBuf {
    let dir = std::env::var("CLAUDE_JOB_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    dir.join(format!(
        "faculties-archive-parallel-{label}-{}-{nanos}.pile",
        std::process::id()
    ))
}

fn run_archive(path: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_archive"))
        .arg("--pile")
        .arg(path)
        .arg("--branch")
        .arg("archive")
        .args(args)
        .output()
        .expect("run archive binary")
}

fn push_commit(
    repo: &mut Repository<Pile>,
    ws: &mut Workspace<Pile>,
    change: TribleSet,
    message: &str,
) -> CommitHandle {
    ws.commit(change, message);
    repo.push(ws).expect("push source commit");
    ws.head().expect("source commit head")
}

fn small_content_commit(ws: &mut Workspace<Pile>, ordinal: usize) -> TribleSet {
    let message = *fucid();
    let content = ws.put::<LongString, _>(format!(
        "parallel archive test document {ordinal} token{}",
        ordinal % 5
    ));
    entity! { ExclusiveId::force_ref(&message) @
        archive::content: content,
    }
    .into()
}

fn multishard_commit() -> TribleSet {
    // One trible beyond the physical boundary forces exactly two leaves.
    // Raw deterministic EAV bytes make construction inexpensive and retain
    // strict canonical order across the 65,536-row split.
    let mut set = TribleSet::new();
    for ordinal in 0..=(1usize << 16) {
        let mut raw = [0u8; 64];
        raw[0] = 1;
        raw[8..16].copy_from_slice(&(ordinal as u64).to_be_bytes());
        raw[16] = 2;
        raw[56..64].copy_from_slice(&(ordinal as u64).to_be_bytes());
        set.insert(&Trible::force_raw(raw).unwrap());
    }
    set
}

fn build_success_source(path: &Path) -> Id {
    std::fs::File::create(path).expect("create source pile");
    let pile = Pile::open(path).expect("open source pile");
    let mut repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
        .expect("create source repository");
    let branch_id = *repo.create_branch("archive", None).expect("create branch");
    let mut ws = repo.pull(branch_id).expect("pull branch");

    // Seventeen BM25/Succinct leaves cross both the level-0 and level-1
    // carry boundaries. Exercise a contentless logical commit in the middle.
    for ordinal in 0..17 {
        let change = small_content_commit(&mut ws, ordinal);
        push_commit(&mut repo, &mut ws, change, "small source commit");
        if ordinal == 7 {
            push_commit(
                &mut repo,
                &mut ws,
                TribleSet::new(),
                "contentless source commit",
            );
        }
    }
    push_commit(
        &mut repo,
        &mut ws,
        multishard_commit(),
        "multi-shard source commit",
    );
    repo.close().expect("close source repository");
    branch_id
}

#[derive(Debug, PartialEq, Eq)]
struct SegmentSnapshot {
    level: u64,
    seq: u64,
    start: Vec<[u8; 32]>,
    end: Vec<[u8; 32]>,
    artifacts: Vec<Vec<([u8; 32], Vec<u8>)>>,
}

#[derive(Debug, PartialEq, Eq)]
struct IndexSnapshot {
    branch_meta: CommitHandle,
    branch_meta_bytes: Vec<u8>,
    succinct: Vec<SegmentSnapshot>,
    bm25: Vec<SegmentSnapshot>,
}

fn snapshot(path: &Path, branch_id: Id) -> IndexSnapshot {
    let mut pile = Pile::open(path).expect("open indexed pile");
    pile.refresh().expect("refresh indexed pile");
    let branch_meta = pile
        .head(branch_id)
        .expect("read branch pin")
        .expect("branch metadata handle");
    let reader = pile.reader().expect("open snapshot reader");
    let branch_blob: Blob<SimpleArchive> = reader.get(branch_meta).expect("branch metadata blob");
    let branch_meta_set: TribleSet = branch_blob
        .clone()
        .try_from_blob()
        .expect("decode branch metadata");
    let succinct_kind = SuccinctRollup::new();
    let bm25_kind = Bm25Rollup::new(reader.clone(), archive::content.id());

    let succinct_manifest = Manifest::from_tribles(&branch_meta_set, &reader, &succinct_kind)
        .expect("typed Succinct manifest");
    let succinct = succinct_manifest
        .ranges()
        .iter()
        .map(|entry| SegmentSnapshot {
            level: entry.level(),
            seq: entry.seq(),
            start: entry
                .range()
                .start()
                .iter()
                .map(|commit| commit.raw)
                .collect(),
            end: entry
                .range()
                .end()
                .iter()
                .map(|commit| commit.raw)
                .collect(),
            artifacts: entry
                .artifacts()
                .iter()
                .map(|artifact| {
                    let raw: Blob<SuccinctArchiveBlob> =
                        reader.get(artifact.raw()).expect("raw Succinct artifact");
                    let rank9: Blob<SuccinctArchiveRank9IndexBlob> = reader
                        .get(artifact.rank9())
                        .expect("Rank9 Succinct artifact");
                    vec![
                        (artifact.raw().raw, raw.bytes.to_vec()),
                        (artifact.rank9().raw, rank9.bytes.to_vec()),
                    ]
                })
                .collect(),
        })
        .collect();
    let bm25_manifest =
        Manifest::from_tribles(&branch_meta_set, &reader, &bm25_kind).expect("typed BM25 manifest");
    let bm25 = bm25_manifest
        .ranges()
        .iter()
        .map(|entry| SegmentSnapshot {
            level: entry.level(),
            seq: entry.seq(),
            start: entry
                .range()
                .start()
                .iter()
                .map(|commit| commit.raw)
                .collect(),
            end: entry
                .range()
                .end()
                .iter()
                .map(|commit| commit.raw)
                .collect(),
            artifacts: entry
                .artifacts()
                .iter()
                .map(|handle| {
                    let blob: Blob<SuccinctBM25Blob> = reader.get(*handle).expect("BM25 artifact");
                    vec![(handle.raw, blob.bytes.to_vec())]
                })
                .collect(),
        })
        .collect();

    let snapshot = IndexSnapshot {
        branch_meta,
        branch_meta_bytes: branch_blob.bytes.to_vec(),
        succinct,
        bm25,
    };
    drop(reader);
    pile.close().expect("close snapshot pile");
    snapshot
}

#[test]
fn serial_and_parallel_windows_publish_identical_index_bytes() {
    let source = temp_pile_path("source");
    let serial = temp_pile_path("serial");
    let parallel = temp_pile_path("parallel");
    let branch_id = build_success_source(&source);
    std::fs::copy(&source, &serial).expect("clone serial pile");
    std::fs::copy(&source, &parallel).expect("clone parallel pile");

    let serial_started = Instant::now();
    let serial_output = run_archive(&serial, &["index", "--prepare-in-flight", "1"]);
    let serial_elapsed = serial_started.elapsed();
    assert!(
        serial_output.status.success(),
        "serial index failed: {}",
        String::from_utf8_lossy(&serial_output.stderr)
    );

    let parallel_started = Instant::now();
    let parallel_output = run_archive(&parallel, &["index", "--prepare-in-flight", "4"]);
    let parallel_elapsed = parallel_started.elapsed();
    assert!(
        parallel_output.status.success(),
        "parallel index failed: {}",
        String::from_utf8_lossy(&parallel_output.stderr)
    );
    eprintln!(
        "synthetic archive index: serial={serial_elapsed:.2?}, parallel={parallel_elapsed:.2?}"
    );

    assert_eq!(snapshot(&serial, branch_id), snapshot(&parallel, branch_id));

    for path in [source, serial, parallel] {
        let _ = std::fs::remove_file(path);
    }
}

fn build_failure_source(path: &Path) -> (Id, Vec<CommitHandle>, usize) {
    std::fs::File::create(path).expect("create failure pile");
    let pile = Pile::open(path).expect("open failure pile");
    let mut repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
        .expect("create failure repository");
    let branch_id = *repo.create_branch("archive", None).expect("create branch");
    let mut ws = repo.pull(branch_id).expect("pull branch");
    let mut commits = Vec::new();
    for ordinal in 0..3 {
        let change = small_content_commit(&mut ws, ordinal);
        commits.push(push_commit(
            &mut repo,
            &mut ws,
            change,
            "valid prefix commit",
        ));
    }

    let bad_ordinal = commits.len();
    let entity = *fucid();
    let missing = Inline::<Handle<LongString>>::new([0xA5; 32]);
    let bad: TribleSet = entity! { ExclusiveId::force_ref(&entity) @
        archive::content: missing,
    }
    .into();
    commits.push(push_commit(
        &mut repo,
        &mut ws,
        bad,
        "unreadable content commit",
    ));
    for ordinal in 3..6 {
        let change = small_content_commit(&mut ws, ordinal);
        commits.push(push_commit(
            &mut repo,
            &mut ws,
            change,
            "valid suffix commit",
        ));
    }
    repo.close().expect("close failure repository");
    (branch_id, commits, bad_ordinal)
}

#[test]
fn preparation_failure_checkpoints_only_the_contiguous_prefix() {
    let path = temp_pile_path("failure");
    let (branch_id, commits, bad_ordinal) = build_failure_source(&path);
    let output = run_archive(&path, &["index", "--prepare-in-flight", "4"]);
    assert!(
        !output.status.success(),
        "invalid content must fail indexing"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("is unreadable"),
        "failure diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut pile = Pile::open(&path).expect("open failed-index pile");
    pile.refresh().expect("refresh failed-index pile");
    let branch_meta_handle = pile
        .head(branch_id)
        .expect("read branch pin")
        .expect("branch metadata");
    let reader = pile.reader().expect("open reader");
    let branch_meta: TribleSet = reader
        .get(branch_meta_handle)
        .expect("load branch metadata");
    let expected = vec![commits[bad_ordinal - 1]];
    let succinct_kind = SuccinctRollup::new();
    let succinct = Manifest::from_tribles(&branch_meta, &reader, &succinct_kind)
        .expect("typed Succinct prefix manifest");
    let bm25_kind = Bm25Rollup::new(reader.clone(), archive::content.id());
    let bm25 = Manifest::from_tribles(&branch_meta, &reader, &bm25_kind)
        .expect("typed BM25 prefix manifest");
    assert_eq!(succinct.frontier(), expected);
    assert_eq!(bm25.frontier(), expected);
    succinct
        .audit_exact_cover(&reader)
        .expect("Succinct prefix cover");
    bm25.audit_exact_cover(&reader).expect("BM25 prefix cover");
    pile.close().expect("close failed-index pile");

    let _ = std::fs::remove_file(path);
}

#[test]
fn contentless_commit_is_a_certified_zero_artifact_range() {
    let path = temp_pile_path("empty");
    std::fs::File::create(&path).expect("create empty source pile");
    let pile = Pile::open(&path).expect("open empty source pile");
    let mut repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
        .expect("create empty source repository");
    let branch_id = *repo.create_branch("archive", None).expect("create branch");
    let mut ws = repo.pull(branch_id).expect("pull branch");
    let source_head = push_commit(
        &mut repo,
        &mut ws,
        TribleSet::new(),
        "contentless source commit",
    );
    repo.close().expect("close empty source repository");

    let output = run_archive(&path, &["index", "--prepare-in-flight", "1"]);
    assert!(
        output.status.success(),
        "empty index failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut pile = Pile::open(&path).expect("open empty indexed pile");
    pile.refresh().expect("refresh empty indexed pile");
    let branch_meta_handle = pile.head(branch_id).unwrap().unwrap();
    let reader = pile.reader().expect("empty manifest reader");
    let branch_meta: TribleSet = reader.get(branch_meta_handle).unwrap();
    let succinct_kind = SuccinctRollup::new();
    let succinct = Manifest::from_tribles(&branch_meta, &reader, &succinct_kind).unwrap();
    let bm25_kind = Bm25Rollup::new(reader.clone(), archive::content.id());
    let bm25 = Manifest::from_tribles(&branch_meta, &reader, &bm25_kind).unwrap();
    assert!(succinct.claims_head(Some(source_head)));
    assert_eq!(succinct.ranges().len(), 1);
    assert_eq!(succinct.ranges()[0].range().start(), [source_head]);
    assert_eq!(succinct.ranges()[0].range().end(), [source_head]);
    assert!(succinct.ranges()[0].artifacts().is_empty());
    assert!(bm25.claims_head(Some(source_head)));
    assert_eq!(bm25.ranges().len(), 1);
    assert_eq!(bm25.ranges()[0].range().start(), [source_head]);
    assert_eq!(bm25.ranges()[0].range().end(), [source_head]);
    assert!(bm25.ranges()[0].artifacts().is_empty());
    drop(reader);
    pile.close().expect("close empty indexed pile");

    let list = run_archive(&path, &["list", "--limit", "10"]);
    assert!(list.status.success() && list.stdout.is_empty());
    let search = run_archive(&path, &["search", "anything"]);
    assert!(search.status.success() && search.stdout.is_empty());

    let _ = std::fs::remove_file(path);
}
