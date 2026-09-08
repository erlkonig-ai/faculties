use faculties::bootstrap::{self, mcp::Bootstrap};
use faculties::mcp::{Faculty, InvalidArguments};
use faculties::out::{Out, Part};
use faculties::storage::initialize_signer;

#[test]
fn native_and_mcp_import_share_exact_idempotent_publication() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("bootstrap.pile");
    let key = directory.path().join("bootstrap.key");
    std::fs::File::create(&pile).unwrap();
    initialize_signer(&pile, Some(&key)).unwrap();
    let first = pollster::block_on(bootstrap::import(&pile, Some(&key))).unwrap();
    let mcp = Bootstrap::new(pile.clone(), Some(key));
    let before = std::fs::metadata(&pile).unwrap().len();
    let mut text = String::new();
    mcp.call(
        "bootstrap_import",
        "{}".to_owned().into(),
        &mut Out::new(&mut |part| {
            let Part::Text { text: value } = part else {
                panic!("non-text bootstrap receipt");
            };
            text.push_str(&value);
            Ok(())
        }),
    )
    .unwrap();
    assert!(text.contains(&hex::encode(first.generation)));
    assert!(text.contains("wiki COMMIT record fingerprint"));
    assert!(text.contains("compass COMMIT record fingerprint"));
    assert_eq!(std::fs::metadata(&pile).unwrap().len(), before);
}

#[test]
fn bootstrap_discovery_and_bad_arguments_do_not_initialize_storage() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("missing.pile");
    let mcp = Bootstrap::new(pile.clone(), None);
    assert_eq!(mcp.tools().len(), 1);
    let error = mcp
        .call(
            "bootstrap_import",
            r#"{"pile":"/other"}"#.to_owned().into(),
            &mut Out::new(&mut |_| panic!("unexpected output")),
        )
        .unwrap_err();
    assert!(error.downcast_ref::<InvalidArguments>().is_some());
    assert!(!pile.exists());
}
