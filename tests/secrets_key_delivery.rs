//! Exercise the actual Secrets local CLI boundary, independently of transport READ.

use std::process::{Command, Output};

use faculties::secrets::{self, storage::SecretsCollection};
use hifitime::Epoch;
use triblespace::core::capability::{
    Capability, CapabilityMode, CapabilityProof, CapabilityResource, CapabilityValidity,
};
use triblespace::core::collection::{
    read_capability, AdmissionPolicy, CollectionPolicy, CollectionStoreExt,
};
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{CapabilityProofStore, SnapshotSource};
use triblespace::core::signing_key_file;
use triblespace::prelude::*;

fn successful(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn default_local_owner_can_add_and_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("owner.pile");
    let key = dir.path().join("owner.key");
    std::fs::File::create(&path).unwrap();
    signing_key_file::init(&key).unwrap();
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_secrets"));
        command.args([
            "--pile",
            path.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
        ]);
        command.env_remove("TRIBLESPACE_COLLECTION_SECRETS");
        command
    };
    let added = successful(
        command()
            .args(["add", "--name", "token", "--value", "local value"])
            .output()
            .unwrap(),
    );
    let secret = added.split_whitespace().nth(1).unwrap();
    assert_eq!(
        successful(
            command()
                .args(["get", "--secret", secret])
                .output()
                .unwrap()
        ),
        "local value"
    );
    assert!(successful(command().arg("list").output().unwrap()).contains("token"));
}

#[test]
fn local_get_and_list_do_not_recheck_expired_replication_or_delivery_authority() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("delivered.pile");
    let owner_path = dir.path().join("owner.key");
    let recipient_path = dir.path().join("recipient.key");
    std::fs::File::create(&path).unwrap();
    let owner = signing_key_file::init(&owner_path).unwrap();
    let recipient = signing_key_file::init(&recipient_path).unwrap();
    let mut pile = Pile::open(&path).unwrap();
    let collection = SecretsCollection::register(
        &mut pile,
        "secrets",
        CollectionPolicy::new(
            AdmissionPolicy::direct(owner.verifying_key()),
            AdmissionPolicy::direct(owner.verifying_key()),
        )
        .with_capability(
            secrets::key_delivery_definition(),
            AdmissionPolicy::direct(owner.verifying_key()),
        ),
    )
    .unwrap();
    for capability in [read_capability(), secrets::key_delivery_capability()] {
        pile.insert_proof(CapabilityProof::issue_root(
            &owner,
            CapabilityResource::from(collection.handle()),
            Capability::new(capability, CapabilityMode::Invoke),
            Some(
                CapabilityValidity::new(
                    Epoch::from_unix_seconds(0.0),
                    Epoch::from_unix_seconds(1.0),
                )
                .unwrap(),
            ),
            recipient.verifying_key(),
        ))
        .unwrap();
    }
    let instant = Epoch::from_unix_seconds(0.0);
    let sealed = secrets::seal_version(
        "already delivered",
        b"still decryptable",
        [recipient.verifying_key()],
        (instant, instant).try_to_inline().unwrap(),
    )
    .unwrap();
    let secret = sealed.secret;
    pile.commit(collection.source(), &owner, sealed.fragment)
        .unwrap();
    assert!(!collection
        .source()
        .reader_is_admitted(&pile.snapshot().unwrap(), recipient.verifying_key(),)
        .unwrap());
    pile.close().unwrap();
    let handle = hex::encode(collection.handle().raw);
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_secrets"));
        command.args([
            "--pile",
            path.to_str().unwrap(),
            "--key",
            recipient_path.to_str().unwrap(),
        ]);
        command.env("TRIBLESPACE_COLLECTION_SECRETS", &handle);
        command
    };
    assert_eq!(
        successful(
            command()
                .args(["get", "--secret", &format!("{secret:x}")])
                .output()
                .unwrap()
        ),
        "still decryptable"
    );
    assert!(successful(command().arg("list").output().unwrap()).contains("already delivered"));
}
