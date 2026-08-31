use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ed25519_dalek::SigningKey;
use tempfile::TempDir;
use triblespace::core::collection::{
    grant_collection_write, CollectionRead, CollectionRecord, CollectionStoreExt,
};
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::SnapshotSource;

struct TestPile {
    _directory: TempDir,
    pile: PathBuf,
    tenant_key: PathBuf,
}

impl TestPile {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("create collection override fixture");
        let pile = directory.path().join("shared.pile");
        let tenant_key = directory.path().join("tenant.key");
        fs::File::create(&pile).expect("create pile");
        faculties::storage::initialize_signer(&pile, Some(&tenant_key))
            .expect("initialize tenant signer");
        Self {
            _directory: directory,
            pile,
            tenant_key,
        }
    }
}

fn run_relations(fixture: &TestPile, collection: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_relations"))
        .arg("--pile")
        .arg(&fixture.pile)
        .arg("--key")
        .arg(&fixture.tenant_key)
        .arg("add")
        .arg("Ada")
        .env("TRIBLESPACE_COLLECTION_RELATIONS", collection)
        .output()
        .expect("run relations")
}

fn commit_count(path: &Path) -> usize {
    let mut pile = Pile::open(path).expect("open pile for record count");
    let snapshot = pile.snapshot().expect("freeze pile for record count");
    let count = snapshot
        .records()
        .expect("read collection records")
        .filter_map(Result::ok)
        .filter(|record| matches!(record, CollectionRecord::Commit(_)))
        .count();
    drop(snapshot);
    pile.close().expect("close pile after record count");
    count
}

#[test]
fn configured_collection_refuses_unauthorized_cli_write_before_append() {
    let fixture = TestPile::new();
    let root = SigningKey::from_bytes(&[0x41; 32]);
    let tenant = faculties::storage::load_signer(&fixture.pile, Some(&fixture.tenant_key))
        .expect("load tenant signer");

    let mut pile = Pile::open(&fixture.pile).expect("open fixture pile");
    let collection = pile
        .collection(
            "relations",
            faculties::collection_names::private_policy(root.verifying_key()),
        )
        .expect("register shared relations collection");
    pile.close().expect("close initialized fixture pile");
    let handle = hex::encode(collection.handle().raw);

    let before_len = fs::metadata(&fixture.pile).unwrap().len();
    let before_commits = commit_count(&fixture.pile);
    let refused = run_relations(&fixture, &handle);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("is not admitted to WRITE"),
        "unexpected diagnostic: {}",
        String::from_utf8_lossy(&refused.stderr),
    );
    assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), before_len);
    assert_eq!(commit_count(&fixture.pile), before_commits);

    let mut pile = Pile::open(&fixture.pile).expect("reopen fixture pile");
    grant_collection_write(
        &mut pile,
        collection.handle(),
        &root,
        tenant.verifying_key(),
    )
    .expect("grant tenant WRITE");
    pile.close().expect("close granted fixture pile");

    let accepted = run_relations(&fixture, &handle);
    assert!(
        accepted.status.success(),
        "granted write failed: {}",
        String::from_utf8_lossy(&accepted.stderr),
    );
    assert_eq!(commit_count(&fixture.pile), before_commits + 1);
}
