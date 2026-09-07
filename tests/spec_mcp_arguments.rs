use std::path::Path;

use anybytes::Bytes;
use anyhow::Result;
use faculties::archive_source::canonical_json;
use faculties::mcp::{Registration, Server};
use faculties::out::Out;
use faculties::spec::{ArgumentValue, Arguments, Invocation, Param, Spec, Verb};

static SPEC: Spec = Spec {
    name: "options",
    about: "Typed options",
    version: None,
    shared: &[
        Param::caller("pile", "Configured pile").ambient(),
        Param::caller("key", "Configured key").ambient().optional(),
    ],
    verbs: &[Verb {
        name: "show",
        about: "Echo native options",
        params: &[
            Param::caller("id", "Identifier").positional(),
            Param::caller("dry-run", "Preview").flag(),
            Param::caller("tag", "Tags").repeated(),
            Param::caller("limit", "Limit").default("10").short('n'),
        ],
    }],
};

fn execute(invocation: &Invocation, output: &mut Out<'_>) -> Result<()> {
    assert_eq!(invocation.require("pile")?, "configured.pile");
    assert_eq!(invocation.get("key"), Some("configured.key"));
    output.text(format!(
        "id={}; dry-run={}; tag={:?}; limit={}",
        invocation.require("id")?,
        invocation.flag("dry-run"),
        invocation.values("tag"),
        invocation.require("limit")?,
    ))
}

fn registrations() -> [Registration; 1] {
    [Registration {
        spec: &SPEC,
        invoke: execute,
        ambient: Arguments::new()
            .with("pile", "configured.pile")
            .with("key", "configured.key"),
    }]
}

fn request(server: &mut Server<'_>, text: &str) -> Option<String> {
    let response = server
        .dispatch(Bytes::from(text.as_bytes().to_vec()))
        .unwrap();
    if let Some(response) = &response {
        canonical_json(Bytes::from(response.as_bytes().to_vec())).expect("valid response JSON");
    }
    response
}

fn initialize(server: &mut Server<'_>) {
    request(server, r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#).unwrap();
    assert!(request(
        server,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
    )
    .is_none());
}

#[test]
fn wire_schema_projects_flags_arrays_defaults_and_ambient_hiding() {
    let registrations = registrations();
    let mut server = Server::new(&registrations).unwrap();
    initialize(&mut server);
    let result = request(
        &mut server,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    )
    .unwrap();
    assert!(
        result.contains(r#""dry-run":{"type":"boolean","description":"Preview","default":false}"#)
    );
    assert!(result.contains(
        r#""tag":{"type":"array","items":{"type":"string"},"description":"Tags","default":[]}"#
    ));
    assert!(result.contains(r#""limit":{"type":"string","description":"Limit","default":"10"}"#));
    assert!(result.contains(r#""required":["id"]"#));
    assert!(!result.contains("pile"));
    assert!(!result.contains("key"));
}

#[test]
fn wire_values_and_omissions_reach_the_same_native_defaults() {
    let registrations = registrations();
    let mut server = Server::new(&registrations).unwrap();
    initialize(&mut server);
    let omitted = request(&mut server, r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"options_show","arguments":{"id":"abcd"}}}"#).unwrap();
    let explicit = request(&mut server, r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"options_show","arguments":{"id":"abcd","dry-run":false,"tag":[]}}}"#).unwrap();
    for result in [omitted, explicit] {
        assert!(result.contains("id=abcd; dry-run=false; tag=[]; limit=10"));
        assert!(result.contains(r#""isError":false"#));
    }
    let supplied = request(&mut server, r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"options_show","arguments":{"id":"abcd","dry-run":true,"tag":["first","first","second"],"limit":"7"}}}"#).unwrap();
    assert!(supplied
        .contains(r#"id=abcd; dry-run=true; tag=[\"first\", \"first\", \"second\"]; limit=7"#));
    assert!(supplied.contains(r#""isError":false"#));
}

#[test]
fn wrong_types_duplicate_arrays_and_ambient_overrides_do_not_invoke() {
    let registrations = [Registration {
        spec: &SPEC,
        invoke: |_, _| panic!("invalid wire arguments reached the handler"),
        ambient: Arguments::new().with("pile", "configured.pile"),
    }];
    let mut server = Server::new(&registrations).unwrap();
    initialize(&mut server);
    for tail in [
        r#""dry-run":"true""#,
        r#""dry-run":[]"#,
        r#""tag":"tag""#,
        r#""tag":true"#,
        r#""tag":["valid",1]"#,
        r#""tag":[["nested"]]"#,
        r#""tag":null"#,
        r#""limit":10"#,
        r#""limit":false"#,
        r#""tag":["first"],"tag":["second"]"#,
        r#""pile":"wrong""#,
        r#""key":false"#,
        r#""unknown":[]"#,
    ] {
        let text = format!(
            r#"{{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{{"name":"options_show","arguments":{{"id":"abcd",{tail}}}}}}}"#
        );
        let response = request(&mut server, &text).unwrap();
        assert!(response.contains(r#""code":-32602"#), "{response}");
        assert!(!response.contains("content"));
    }
    assert!(request(&mut server, r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"options_show","arguments":{"id":"abcd","dry-run":true,"tag":["valid"]}}}"#).is_none());
}

static PATH_SPEC: Spec = Spec {
    name: "paths",
    about: "Native path arguments",
    version: None,
    shared: &[
        Param::caller("pile", "Configured pile").path().ambient(),
        Param::caller("key", "Configured key")
            .path()
            .ambient()
            .optional(),
    ],
    verbs: &[Verb {
        name: "add",
        about: "Accept a native path",
        params: &[
            Param::caller("path", "Input path").path().positional(),
            Param::caller("base", "Base directory").path().default("."),
        ],
    }],
};

#[test]
fn wire_string_paths_reach_native_path_arguments() {
    let registrations = [Registration {
        spec: &PATH_SPEC,
        invoke: |invocation, output| {
            assert_eq!(invocation.require_path("path")?, Path::new("dir/é.txt"));
            assert_eq!(invocation.require_path("base")?, Path::new("."));
            assert_eq!(
                invocation.require_path("pile")?,
                Path::new("configured.pile")
            );
            assert_eq!(invocation.path("key"), Some(Path::new("configured.key")));
            assert!(invocation.get("path").is_none());
            output.text("native paths accepted")
        },
        ambient: Arguments::new()
            .with_value("pile", ArgumentValue::Path("configured.pile".into()))
            .with("key", "configured.key"),
    }];
    let mut server = Server::new(&registrations).unwrap();
    initialize(&mut server);
    let schema = request(
        &mut server,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    )
    .unwrap();
    assert!(schema.contains(r#""path":{"type":"string","description":"Input path"}"#));
    assert!(
        schema.contains(r#""base":{"type":"string","description":"Base directory","default":"."}"#)
    );
    assert!(!schema.contains("pile"));
    assert!(!schema.contains("key"));
    let response = request(&mut server, r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"paths_add","arguments":{"path":"dir/\u00e9.txt"}}}"#).unwrap();
    assert!(response.contains("native paths accepted"));
    assert!(response.contains(r#""isError":false"#));
}

#[test]
fn wire_path_types_and_ambient_overrides_fail_before_invocation() {
    let registrations = [Registration {
        spec: &PATH_SPEC,
        invoke: |_, _| panic!("invalid path arguments reached the handler"),
        ambient: Arguments::new().with("pile", "configured.pile"),
    }];
    let mut server = Server::new(&registrations).unwrap();
    initialize(&mut server);
    for arguments in [
        r#"{"path":false}"#,
        r#"{"path":["input.txt"]}"#,
        r#"{"path":10}"#,
        r#"{"path":null}"#,
        r#"{"path":"input.txt","pile":"wrong.pile"}"#,
        r#"{"path":"input.txt","key":"wrong.key"}"#,
    ] {
        let text = format!(
            r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"paths_add","arguments":{arguments}}}}}"#
        );
        let response = request(&mut server, &text).unwrap();
        assert!(response.contains(r#""code":-32602"#), "{response}");
        assert!(!response.contains("content"));
    }
}
