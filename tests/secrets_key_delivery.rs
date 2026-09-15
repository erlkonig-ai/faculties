//! Exercise the actual Secrets local CLI boundary, independently of transport READ.

use std::process::{Command, Output};

use faculties::secrets::{self, storage::SecretsCollection};
use hifitime::Epoch;
use triblespace::core::collection::{
    AdmissionPolicy, CollectionPolicy, CollectionRead, CollectionRealizationError,
    CollectionStoreExt,
};
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::SnapshotSource;
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
fn legacy_local_get_and_list_need_no_replication_or_delivery_authority() {
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

    // Possessing a delivered envelope does not grant the recipient WRITE on
    // either derived collection. Explicit production still refuses that key.
    let before = pile
        .snapshot()
        .unwrap()
        .records()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let error = pollster::block_on(collection.ensure(&mut pile, &recipient))
        .err()
        .expect("recipient cannot publish the missing Secrets cover");
    assert!(matches!(
        error.downcast_ref::<CollectionRealizationError>(),
        Some(CollectionRealizationError::UnauthorizedProducer { collection: target })
            if *target == collection.succinct().handle()
    ));

    // Ordinary reads tolerate only that lack of production authority. The
    // target is not realized yet, so its honest read-only view is empty.
    let observed = pollster::block_on(secrets::storage::ensure_and_snapshot(
        &mut pile, collection, &recipient,
    ))
    .unwrap();
    assert!(observed.support().is_empty());
    drop(observed);
    assert_eq!(
        pile.snapshot()
            .unwrap()
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        before,
        "read-only fallback publishes no derivations",
    );

    // The actual owner publishes the encodings. Subsequent local readers
    // reuse that complete cover without new WRITE or current READ/delivery.
    drop(
        pollster::block_on(secrets::storage::ensure_and_snapshot(
            &mut pile, collection, &owner,
        ))
        .unwrap(),
    );
    let produced_records = pile
        .snapshot()
        .unwrap()
        .records()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
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

    let mut pile = Pile::open(&path).unwrap();
    assert_eq!(
        pile.snapshot()
            .unwrap()
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        produced_records,
        "foreign get/list reuse the owner's equations without publishing records",
    );
    pile.close().unwrap();
}

#[test]
fn cli_grant_and_selected_maintenance_do_not_grant_collection_access() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("selected.pile");
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
        ),
    )
    .unwrap();
    pile.close().unwrap();
    let handle = hex::encode(collection.handle().raw);
    let command = |key: &std::path::Path| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_secrets"));
        command.args([
            "--pile",
            path.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
        ]);
        command.env("TRIBLESPACE_COLLECTION_SECRETS", &handle);
        command
    };
    let add = |value: &str| {
        successful(
            command(&owner_path)
                .args(["add", "--name", "token", "--value", value])
                .output()
                .unwrap(),
        )
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned()
    };
    let first = add("first");
    let second = add("second");
    let grant = successful(
        command(&owner_path)
            .args([
                "grant",
                "--secret",
                &first,
                "--recipient",
                &hex::encode(recipient.verifying_key().to_bytes()),
                "--expires-at",
                "2099-01-01T00:00:00Z",
            ])
            .output()
            .unwrap(),
    );
    assert!(grant.starts_with("AUTH blake3:"));
    assert_eq!(
        successful(
            command(&owner_path)
                .args(["maintain", "--secret", &first])
                .output()
                .unwrap()
        )
        .trim(),
        "added 1 recipient envelope(s)"
    );
    // Let the owner realize the newly appended envelope before the read-only key attaches.
    successful(
        command(&owner_path)
            .args(["maintain", "--secret", &first])
            .output()
            .unwrap(),
    );
    assert_eq!(
        successful(
            command(&recipient_path)
                .args(["get", "--secret", &first])
                .output()
                .unwrap()
        ),
        "first"
    );
    assert!(!command(&recipient_path)
        .args(["get", "--secret", &second])
        .output()
        .unwrap()
        .status
        .success());
    let mut pile = Pile::open(&path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    assert!(!collection
        .source()
        .reader_is_admitted(&snapshot, recipient.verifying_key())
        .unwrap());
    assert!(!collection
        .source()
        .writer_is_admitted(&snapshot, recipient.verifying_key())
        .unwrap());
    drop(snapshot);
    pile.close().unwrap();
}
