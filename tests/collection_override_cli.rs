use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use ed25519_dalek::SigningKey;
use tempfile::TempDir;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::collection::{
    grant_collection_write, CollectionRead, CollectionRecord, CollectionSnapshotExt,
    CollectionStoreExt,
};
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{BlobStoreList, SnapshotSource};

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
        .env_remove("TRIBLESPACE_PEERS")
        .output()
        .expect("run relations")
}

#[test]
fn configured_collection_retains_offline_cli_commit_until_write_is_granted() {
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

    // Local publication retains a signed claim even without present WRITE
    // admission. Admission is a property of the reader's frozen evidence.
    let published = run_relations(&fixture, &handle);
    eprintln!(
        "fixture CLI stdout: {}",
        String::from_utf8_lossy(&published.stdout)
    );
    eprintln!(
        "fixture CLI stderr: {}",
        String::from_utf8_lossy(&published.stderr)
    );
    assert!(
        published.status.success(),
        "local publication failed: {}",
        String::from_utf8_lossy(&published.stderr),
    );

    let mut pile = Pile::open(&fixture.pile).expect("reopen fixture pile");
    let frozen = pile.snapshot().expect("freeze pre-grant evidence");
    let original = {
        let mut commits = frozen
            .records()
            .expect("read retained collection records")
            .map(|record| record.expect("decode retained record"))
            .filter_map(|record| match record {
                CollectionRecord::Commit(commit) => Some(commit),
                _ => None,
            });
        let commit = commits.next().expect("the CLI retained one signed claim");
        assert!(commits.next().is_none(), "one invocation emits one COMMIT");
        commit
    };
    assert_eq!(original.collection(), collection.handle());
    assert_eq!(original.public_key().raw, tenant.verifying_key().to_bytes());
    let member = Handle::<SimpleArchive>::from_hash(original.data());
    assert!(frozen.contains_blob(member).unwrap());
    let unadmitted = frozen
        .collection(collection)
        .expect("observe collection before the grant");
    assert!(unadmitted.support().is_empty());
    assert!(unadmitted.cover().is_empty());
    eprintln!("before grant: retained_commits=1 admitted_members=0");

    grant_collection_write(
        &mut pile,
        collection.handle(),
        &root,
        tenant.verifying_key(),
    )
    .expect("grant tenant WRITE");
    // There is deliberately no second CLI call: the new evidence admits the
    // original member, without another emission, signature, or entity id.
    let after = pile.snapshot().expect("freeze post-grant evidence");
    let admitted = after
        .collection(collection)
        .expect("observe collection after the grant");
    assert_eq!(admitted.support().len(), 1);
    assert!(admitted.support().contains(member));
    assert_eq!(admitted.cover().len(), 1);
    assert!(admitted.cover().contains(member));
    assert!(after
        .records()
        .expect("read post-grant collection records")
        .map(|record| record.expect("decode post-grant record"))
        .filter_map(|record| match record {
            CollectionRecord::Commit(commit) => Some(commit),
            _ => None,
        })
        .eq(std::iter::once(original)));
    assert!(frozen
        .collection(collection)
        .expect("reobserve the frozen pre-grant evidence")
        .support()
        .is_empty());
    assert!(unadmitted.support().is_empty());
    assert!(unadmitted.cover().is_empty());
    eprintln!("after grant: retained_commits=1 admitted_members=1");
    pile.close().expect("close granted fixture pile");
}
