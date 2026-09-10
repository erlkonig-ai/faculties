//! Direct library operations plus explicit CLI/MCP projections of the same
//! additive Atlas collection. Fixtures are local; no process environment is
//! mutated and no frontend is needed to retrieve an AtlasEntry.

use std::fs::File;
use std::path::PathBuf;

use anybytes::Bytes;
use anyhow::Result;
use faculties::atlas::{cli, mcp::Atlas, AtlasEntry, Store};
use faculties::mcp::{Faculty, InvalidArguments};
use faculties::out::{Out, Part};
use faculties::schemas::atlas::DEFAULT_SCOPE_ID;
use faculties::spec::CliRequest;
use faculties::storage::{initialize_signer, publish_fragment};
use triblespace::core::metadata;
use triblespace::prelude::blobencodings::UTF8String;
use triblespace::prelude::*;

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, AtlasEntry) {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("atlas.pile");
    let key = directory.path().join("atlas.key");
    File::create(&pile).unwrap();
    initialize_signer(&pile, Some(&key)).unwrap();
    let id = fucid();
    let tag = fucid();
    let member = fucid();
    let mut fragment = Fragment::empty();
    let names = ["Beta", "Alpha"].map(|name| fragment.put::<UTF8String, _>(name.to_owned()));
    let descriptions = ["Second description", "First description"]
        .map(|description| fragment.put::<UTF8String, _>(description.to_owned()));
    let modules = ["crate::beta", "crate::alpha"]
        .map(|module| fragment.put::<UTF8String, _>(module.to_owned()));
    fragment += entity! { &id @
        metadata::name*: names,
        metadata::description*: descriptions,
        metadata::source_module*: modules,
        metadata::tag: &tag,
    };
    fragment += entity! { &member @ metadata::tag: &id };
    publish_fragment(&pile, Some(&key), DEFAULT_SCOPE_ID, fragment).unwrap();
    let expected = AtlasEntry {
        id: id.id,
        names: vec!["Alpha".into(), "Beta".into()],
        descriptions: vec!["First description".into(), "Second description".into()],
        source_modules: vec!["crate::alpha".into(), "crate::beta".into()],
        tags: vec![tag.id],
        members: vec![member.id],
    };
    (directory, pile, key, expected)
}

fn collect_text(operation: impl FnOnce(&mut Out<'_>) -> Result<()>) -> Result<String> {
    let mut text = String::new();
    operation(&mut Out::new(&mut |part| {
        match part {
            Part::Text { text: emitted } => text.push_str(&emitted),
            other => panic!("Atlas emitted non-text content: {other:?}"),
        }
        Ok(())
    }))?;
    Ok(text)
}

#[test]
fn direct_store_reads_owned_variants_and_refreshes_between_operations() {
    let (_directory, pile, key, expected) = fixture();
    let store = Store::open(&pile, Some(&key)).unwrap();
    let before = store.list().unwrap();
    assert_eq!(before, [expected.clone()]);
    assert_eq!(
        store.show(&format!("  {:X}  ", expected.id)).unwrap(),
        expected
    );
    assert!(store
        .show("")
        .unwrap_err()
        .to_string()
        .contains("prefix is empty"));
    assert!(store
        .show("not-an-id")
        .unwrap_err()
        .to_string()
        .contains("no id matches"));

    let mut addition = Fragment::empty();
    let name = addition.put::<UTF8String, _>("Gamma".to_owned());
    addition += entity! { ExclusiveId::force_ref(&expected.id) @ metadata::name: name };
    publish_fragment(&pile, Some(&key), DEFAULT_SCOPE_ID, addition).unwrap();
    let mut after = expected.clone();
    after.names.push("Gamma".into());
    assert_eq!(store.show(&format!("{:x}", expected.id)).unwrap(), after);
    assert_eq!(
        before,
        [expected],
        "the earlier returned observation did not change"
    );
    store.close().unwrap();
}

#[test]
fn explicit_cli_and_mcp_render_the_same_lossless_metadata() {
    let (_directory, pile, key, entry) = fixture();
    let atlas = Atlas::new(pile.clone(), Some(key.clone()));
    let id = format!("{:x}", entry.id);
    let expected_list = format!(
        "{id} Alpha / Beta [2 name variants] @crate::alpha / crate::beta \
         [tags: {:x}] [groups: {:x}] - First description / Second description\n",
        entry.tags[0], entry.members[0],
    );
    let expected_show = format!(
        "id: {id}\nname: Alpha\nname: Beta\ndescription: First description\n\
         description: Second description\nsource_module: crate::alpha\n\
         source_module: crate::beta\ntags: {:x}\ngrouped_by: {:x}\n",
        entry.tags[0], entry.members[0],
    );
    for (verb, expected) in [("list", expected_list), ("show", expected_show)] {
        let mut args = vec![
            "atlas".into(),
            "--pile".into(),
            pile.as_os_str().to_owned(),
            "--key".into(),
            key.as_os_str().to_owned(),
            verb.into(),
        ];
        if verb == "show" {
            args.push(id.clone().into());
        }
        let CliRequest::Invoke(invocation) = cli::SPEC.lower_cli_from(args).unwrap() else {
            panic!("expected an Atlas CLI request");
        };
        let cli_text = collect_text(|out| cli::execute(&invocation, out)).unwrap();
        let arguments = if verb == "show" {
            serde_json::json!({ "id": id })
        } else {
            serde_json::json!({})
        };
        let arguments = Bytes::from(serde_json::to_vec(&arguments).unwrap());
        let mcp_text =
            collect_text(|out| atlas.call(&format!("atlas_{verb}"), arguments, out)).unwrap();
        assert_eq!(cli_text, expected);
        assert_eq!(mcp_text, expected);
    }
}

#[test]
fn mcp_arguments_are_typed_and_cannot_replace_configured_storage() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("does-not-exist.pile");
    let key = directory.path().join("does-not-exist.key");
    let atlas = Atlas::new(pile.clone(), Some(key.clone()));
    assert_eq!(
        atlas
            .tools()
            .iter()
            .map(|tool| tool.name)
            .collect::<Vec<_>>(),
        ["atlas_list", "atlas_show"]
    );
    for tool in atlas.tools() {
        let schema: serde_json::Value = serde_json::from_str(tool.input_schema).unwrap();
        assert_eq!(schema["additionalProperties"], false);
        let properties = schema["properties"].as_object().unwrap();
        assert!(properties.keys().all(|key| key == "id"));
    }
    for (tool, arguments) in [
        ("atlas_list", r#"{"pile":"caller.pile"}"#),
        ("atlas_list", r#"{"key":"caller.key"}"#),
        ("atlas_list", "null"),
        ("atlas_show", "{}"),
        ("atlas_show", r#"{"id":42}"#),
        ("atlas_show", r#"{"id":"abc","key":"caller.key"}"#),
        ("atlas_show", r#"{"id":"first","id":"second"}"#),
    ] {
        let error = atlas
            .call(
                tool,
                Bytes::from(arguments.as_bytes().to_vec()),
                &mut Out::new(&mut |_| panic!("invalid arguments emitted output")),
            )
            .unwrap_err();
        assert!(
            error.downcast_ref::<InvalidArguments>().is_some(),
            "{error:#}"
        );
    }
    assert!(!pile.exists());
    assert!(!key.exists());
}
