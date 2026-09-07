//! One initialized MCP session exercises the planning, messaging, and Wiki
//! adapters against the same local pile. No network, ambient persona, protocol
//! subprocess, or model runtime is needed for this workflow.

use std::fs::File;
use std::path::PathBuf;

use base64::Engine as _;
use faculties::mcp::Server;
use faculties::relations::{person_fragment, ProfileInput};
use faculties::schemas::relations::DEFAULT_SCOPE_ID;
use faculties::storage::{initialize_signer, publish_fragment};
use faculties::{compass, message, wiki};
use serde_json::{json, Value};
use triblespace::prelude::*;

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("office.pile");
    let key = directory.path().join("office.key");
    File::create(&pile).unwrap();
    initialize_signer(&pile, Some(&key)).unwrap();
    let mut people = Fragment::empty();
    for label in ["alice", "bob"] {
        people += person_fragment(
            fucid().id,
            ProfileInput {
                label: label.into(),
                ..Default::default()
            },
        )
        .unwrap()
        .0;
    }
    publish_fragment(&pile, Some(&key), DEFAULT_SCOPE_ID, people).unwrap();
    (directory, pile, key)
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
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "office-test", "version": "1"}}
        }),
    )
    .unwrap();
    assert!(response.get("error").is_none(), "{response}");
    assert!(request(
        server,
        json!({
            "jsonrpc": "2.0", "method": "notifications/initialized"
        })
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
        .expect("native write receipt contains its id")
        .to_owned()
}

#[test]
fn one_session_writes_and_reads_all_three_faculties() {
    let (_directory, pile, key) = fixture();
    let compass = compass::mcp::Compass::new(pile.clone(), Some(key.clone()));
    let message = message::mcp::Message::new(pile.clone(), Some(key.clone()));
    let wiki = wiki::mcp::Wiki::new(pile, Some(key));
    let mut server = Server::new(&[&compass, &message, &wiki]).unwrap();
    initialize(&mut server);

    let original = "One shared office.\nNo trailing newline";
    let revision = id(&call(
        &mut server,
        "wiki_create",
        json!({
            "title": "Release notes", "content": original, "tags": ["delivery"]
        }),
    ));
    let successor = id(&call(
        &mut server,
        "wiki_edit",
        json!({
            "id": revision, "content": "Updated through the same session."
        }),
    ));
    let current = text(&call(&mut server, "wiki_show", json!({"id": revision})));
    assert!(
        current.contains("Updated through the same session."),
        "{current}"
    );
    let exported = call(
        &mut server,
        "wiki_export",
        json!({"id": revision, "exact": true}),
    );
    assert_eq!(exported["content"].as_array().unwrap().len(), 1);
    assert_eq!(exported["content"][0]["type"], "resource");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(exported["content"][0]["resource"]["blob"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        bytes,
        original.as_bytes(),
        "exact export preserves the old revision"
    );

    let goal = id(&call(
        &mut server,
        "compass_add",
        json!({
            "title": "Deliver the report", "tags": ["delivery"],
            "note": format!("Discussed in [the wiki](wiki:{successor})."),
            "persona": "alice"
        }),
    ));
    let literal = "@/this/path/must/not/be/read";
    call(
        &mut server,
        "compass_note",
        json!({
            "id": goal, "note": literal, "persona": "alice"
        }),
    );
    call(
        &mut server,
        "compass_move",
        json!({
            "id": goal, "status": "doing", "persona": "alice"
        }),
    );
    let shown = text(&call(&mut server, "compass_show", json!({"id": goal})));
    assert!(shown.contains(literal), "{shown}");
    assert!(shown.contains("doing"), "{shown}");

    let sent = id(&call(
        &mut server,
        "message_send",
        json!({
            "from": "alice", "to": "bob", "text": "@-"
        }),
    ));
    let inbox = text(&call(
        &mut server,
        "message_list",
        json!({
            "reader": "bob", "unread": true
        }),
    ));
    assert!(inbox.contains(&sent), "{inbox}");
    assert!(inbox.contains("@-"), "{inbox}");
    call(&mut server, "message_ack", json!({"id": sent, "by": "bob"}));
    call(&mut server, "message_ack", json!({"id": sent, "by": "bob"}));
    let unread = text(&call(
        &mut server,
        "message_list",
        json!({
            "reader": "bob", "unread": true
        }),
    ));
    assert!(
        !unread.contains(&sent),
        "acknowledgements are idempotent: {unread}"
    );
}

#[test]
fn invalid_cross_frontend_arguments_and_notifications_cannot_open_storage() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("must-not-exist.pile");
    let compass = compass::mcp::Compass::new(pile.clone(), None);
    let message = message::mcp::Message::new(pile.clone(), None);
    let wiki = wiki::mcp::Wiki::new(pile.clone(), None);
    let mut server = Server::new(&[&compass, &message, &wiki]).unwrap();
    initialize(&mut server);
    for (name, arguments) in [
        (
            "compass_add",
            json!({"title": "task", "pile": "/forbidden"}),
        ),
        (
            "compass_note",
            json!({"id": "abcd", "note": ["not", "text"]}),
        ),
        (
            "message_send",
            json!({"to": "bob", "text": "missing explicit sender"}),
        ),
        (
            "message_ack_all",
            json!({"by": "bob", "from": "alice", "key": "/forbidden"}),
        ),
        (
            "wiki_create",
            json!({"title": "page", "content": "text", "path": "/forbidden"}),
        ),
        ("wiki_export", json!({"id": "abcd", "exact": "true"})),
        ("wiki_check", json!({"compile": true})),
    ] {
        let response = request(
            &mut server,
            json!({
                "jsonrpc": "2.0", "id": name, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}
            }),
        )
        .unwrap();
        assert_eq!(response["error"]["code"], -32602, "{response}");
        assert!(!pile.exists());
    }
    for (name, arguments) in [
        ("compass_add", json!({"title": "not published"})),
        (
            "message_send",
            json!({"from": "alice", "to": "bob", "text": "not sent"}),
        ),
        (
            "wiki_create",
            json!({"title": "not published", "content": "text"}),
        ),
    ] {
        assert!(request(
            &mut server,
            json!({
                "jsonrpc": "2.0", "method": "tools/call",
                "params": {"name": name, "arguments": arguments}
            })
        )
        .is_none());
        assert!(!pile.exists(), "notification calls must not perform writes");
    }
    assert_eq!(
        request(
            &mut server,
            json!({
                "jsonrpc": "2.0", "id": "still-alive", "method": "ping"
            })
        )
        .unwrap()["result"],
        json!({})
    );
}
