//! Aggregate storage belongs to the catalog, not a tool call or MCP session.
//! All payloads are local text; the tests need no network, models, or hardware.

use std::fs::{self, File};
use std::path::PathBuf;

use faculties::compass::{AddOptions, Compass};
use faculties::mcp::catalog::{Catalog, Config};
use faculties::mcp::Server;
use faculties::storage::initialize_signer;
use serde_json::{json, Value};

struct Fixture {
    _directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("office.pile");
        let key = directory.path().join("office.key");
        File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            _directory: directory,
            pile,
            key,
        }
    }

    fn catalog(&self) -> Catalog {
        let mut config = Config::new(self.pile.clone());
        config.key = Some(self.key.clone());
        Catalog::new(config)
    }
}

fn request(server: &mut Server<'_>, value: Value) -> Option<Value> {
    server
        .dispatch(serde_json::to_vec(&value).unwrap().into())
        .unwrap()
        .map(|response| serde_json::from_str(&response).unwrap())
}

fn initialize(server: &mut Server<'_>) {
    let response = request(
        server,
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "storage-lifetime-test", "version": "1"}
            }
        }),
    )
    .unwrap();
    assert!(response.get("error").is_none(), "{response}");
    assert!(request(
        server,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .is_none());
}

fn call(server: &mut Server<'_>, name: &str, arguments: Value) -> Value {
    let response = request(
        server,
        json!({
            "jsonrpc": "2.0", "id": name, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}
        }),
    )
    .unwrap();
    assert!(response.get("error").is_none(), "{response}");
    assert_eq!(response["result"]["isError"], false, "{response}");
    response["result"].clone()
}

fn text(result: &Value) -> String {
    result["content"]
        .as_array()
        .unwrap()
        .iter()
        .map(|part| {
            assert_eq!(part["type"], "text", "{part}");
            part["text"].as_str().unwrap()
        })
        .collect()
}

fn id(result: &Value) -> String {
    text(result)
        .split(|character: char| !character.is_ascii_hexdigit())
        .find(|word| word.len() == 32)
        .expect("native write receipt contains an id")
        .to_owned()
}

#[test]
fn catalog_retains_one_open_pile_across_tools_adapters_and_protocol_sessions() {
    let fixture = Fixture::new();
    let renamed = fixture.pile.with_file_name("still-open.pile");
    let catalog = fixture.catalog();
    let registrations = catalog.registrations();
    let goal;

    {
        let mut first = Server::new(&registrations).unwrap();
        initialize(&mut first);
        goal = id(&call(
            &mut first,
            "compass_add",
            json!({"title": "shared-pile-record"}),
        ));

        // Reopening the configured pathname cannot find the original data.
        // The explicit signer path remains valid, independently of that name.
        fs::rename(&fixture.pile, &renamed).unwrap();
        let listed = text(&call(&mut first, "compass_list", json!({})));
        assert!(listed.contains("shared-pile-record"), "{listed}");
        assert!(
            !fixture.pile.exists(),
            "a tool reopened the configured pathname"
        );
    }

    {
        // Discarding protocol state must not discard catalog-owned storage.
        let mut second = Server::new(&registrations).unwrap();
        initialize(&mut second);
        call(&mut second, "relations_add", json!({"label": "alice"}));
        call(&mut second, "relations_add", json!({"label": "bob"}));

        // These adapters borrow the local Pile underneath the shared Peer.
        // A resident touch declaration does not access a device or media model.
        call(
            &mut second,
            "body_capture",
            json!({"modality": "touch", "pose": "fixture pose", "note": "first resident touch"}),
        );
        let captures = text(&call(&mut second, "body_list", json!({})));
        assert!(captures.contains("first resident touch"), "{captures}");
        assert!(!captures.contains("second resident touch"), "{captures}");
        call(
            &mut second,
            "status_set",
            json!({"persona": "alice", "text": "first local-only status"}),
        );
        let statuses = text(&call(&mut second, "status_list", json!({})));
        assert!(statuses.contains("first local-only status"), "{statuses}");
        assert!(!statuses.contains("second local-only status"), "{statuses}");
        assert!(
            !fixture.pile.exists(),
            "a local-only adapter reopened the pathname"
        );

        // Atlas retains its native reader in the adapter; listing it must
        // neither reopen nor close the application-owned backend.
        call(&mut second, "atlas_list", json!({}));

        // Continue through Peer consumers after the local guards are released.
        call(
            &mut second,
            "message_send",
            json!({"from": "alice", "to": "bob", "text": "one resident peer"}),
        );
        let inbox = text(&call(
            &mut second,
            "message_list",
            json!({"reader": "bob", "unread": true}),
        ));
        assert!(inbox.contains("one resident peer"), "{inbox}");

        call(
            &mut second,
            "files_add",
            json!({"data": "c2hhcmVkIHN0b3Jl", "name": "resident.txt", "mime": "text/plain"}),
        );
        let files = text(&call(&mut second, "files_list", json!({})));
        assert!(files.contains("resident.txt"), "{files}");

        let revision = id(&call(
            &mut second,
            "wiki_create",
            json!({"title": "Resident Wiki", "content": "One live store.", "force": true}),
        ));
        let wiki = text(&call(&mut second, "wiki_show", json!({"id": revision})));
        assert!(wiki.contains("One live store."), "{wiki}");

        // The local-only readers must take fresh snapshots on their next calls.
        // Distinct status windows avoid depending on wall-clock ordering.
        call(
            &mut second,
            "body_capture",
            json!({"modality": "touch", "pose": "fixture pose", "note": "second resident touch"}),
        );
        let captures = text(&call(&mut second, "body_list", json!({})));
        assert!(captures.contains("first resident touch"), "{captures}");
        assert!(captures.contains("second resident touch"), "{captures}");
        call(
            &mut second,
            "status_set",
            json!({"persona": "bob", "text": "second local-only status"}),
        );
        let statuses = text(&call(&mut second, "status_list", json!({})));
        assert!(statuses.contains("first local-only status"), "{statuses}");
        assert!(statuses.contains("second local-only status"), "{statuses}");

        call(
            &mut second,
            "compass_move",
            json!({"id": goal, "status": "doing", "persona": "alice"}),
        );
        let overview = text(&call(
            &mut second,
            "orient_show",
            json!({"evaluate_habits": false}),
        ));
        assert!(overview.contains("shared-pile-record"), "{overview}");
        assert!(overview.contains("second local-only status"), "{overview}");
        assert!(
            !fixture.pile.exists(),
            "an adapter reopened the configured pathname"
        );
    }

    catalog.close().unwrap();
    assert!(!fixture.pile.exists());
    let persisted = Compass::new(renamed, Some(fixture.key.clone()))
        .show(&goal)
        .unwrap();
    assert!(persisted.contains("shared-pile-record"), "{persisted}");
    assert!(persisted.contains("doing"), "{persisted}");
}

#[test]
fn a_live_catalog_observes_later_appends_from_an_independent_writer() {
    let fixture = Fixture::new();
    let catalog = fixture.catalog();
    let registrations = catalog.registrations();
    let mut server = Server::new(&registrations).unwrap();
    initialize(&mut server);
    let before = text(&call(&mut server, "compass_list", json!({})));
    assert!(!before.contains("later external append"), "{before}");

    // The normal one-shot native operation opens another peer and closes it,
    // while the catalog keeps its own original peer and frozen prior read.
    Compass::new(fixture.pile.clone(), Some(fixture.key.clone()))
        .add("later external append", AddOptions::default())
        .unwrap();

    let after = text(&call(&mut server, "compass_list", json!({})));
    assert!(after.contains("later external append"), "{after}");
    catalog.finish(Ok(())).unwrap();
}

#[test]
fn independently_configured_catalogs_keep_their_piles_isolated() {
    let left_fixture = Fixture::new();
    let right_fixture = Fixture::new();
    let left_catalog = left_fixture.catalog();
    let right_catalog = right_fixture.catalog();
    let left_registrations = left_catalog.registrations();
    let right_registrations = right_catalog.registrations();
    let mut left = Server::new(&left_registrations).unwrap();
    let mut right = Server::new(&right_registrations).unwrap();
    initialize(&mut left);
    initialize(&mut right);
    call(&mut left, "compass_add", json!({"title": "left-only-goal"}));
    call(
        &mut right,
        "compass_add",
        json!({"title": "right-only-goal"}),
    );

    for _ in 0..2 {
        let left_goals = text(&call(&mut left, "compass_list", json!({})));
        let right_goals = text(&call(&mut right, "compass_list", json!({})));
        assert!(left_goals.contains("left-only-goal"), "{left_goals}");
        assert!(!left_goals.contains("right-only-goal"), "{left_goals}");
        assert!(right_goals.contains("right-only-goal"), "{right_goals}");
        assert!(!right_goals.contains("left-only-goal"), "{right_goals}");
    }
    left_catalog.close().unwrap();
    right_catalog.close().unwrap();
}

#[test]
fn discovery_and_closing_an_unused_catalog_do_not_open_storage() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = Config::new(directory.path().join("never-opened.pile"));
    config.key = Some(directory.path().join("never-read.key"));
    let catalog = Catalog::new(config);
    let registrations = catalog.registrations();

    for _ in 0..2 {
        let mut server = Server::new(&registrations).unwrap();
        initialize(&mut server);
        let response = request(
            &mut server,
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        )
        .unwrap();
        assert!(response.get("error").is_none(), "{response}");
        let tools = response["result"]["tools"].as_array().unwrap();
        for name in [
            "compass_list",
            "files_list",
            "message_list",
            "orient_show",
            "relations_list",
            "wiki_list",
        ] {
            assert!(tools.iter().any(|tool| tool["name"] == name), "{name}");
        }
    }

    catalog.finish(Ok(())).unwrap();
    assert_eq!(directory.path().read_dir().unwrap().count(), 0);
}
