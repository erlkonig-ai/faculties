//! Purpose-built MCP argument types, independent of the CLI grammar.

use std::cell::Cell;
use std::path::Path;

use anybytes::Bytes;
use anyhow::{Context, Result};
use faculties::archive_source::canonical_json;
use faculties::mcp::{decode_arguments, Faculty, InvalidArguments, Server, Tool};
use faculties::out::Out;
use serde::Deserialize;

static TOOLS: &[Tool] = &[Tool {
    name: "options_show",
    description: "Echo typed MCP options",
    input_schema: r#"{
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "dry_run": {"type": "boolean", "default": false},
            "tags": {"type": "array", "items": {"type": "string"}, "default": []},
            "limit": {"type": "integer", "minimum": 0, "maximum": 4294967295, "default": 10},
            "window": {
                "type": ["object", "null"],
                "properties": {
                    "start": {"type": "number"},
                    "end": {"type": "number"}
                },
                "required": ["start", "end"],
                "additionalProperties": false
            }
        },
        "required": ["id"],
        "additionalProperties": false
    }"#,
}];

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Window {
    start: f64,
    end: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OptionsArguments {
    id: String,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default = "default_limit")]
    limit: u32,
    #[serde(default, deserialize_with = "faculties::mcp::object::optional")]
    window: Option<Window>,
}

fn default_limit() -> u32 {
    10
}

struct Options<'a> {
    root: &'a Path,
    calls: Cell<usize>,
}

impl Faculty for Options<'_> {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }

    fn call(&self, name: &str, arguments: Bytes, output: &mut Out<'_>) -> Result<()> {
        assert_eq!(name, "options_show");
        let arguments: OptionsArguments =
            decode_arguments(arguments).context("decode options before invoking the operation")?;
        // These represent the beginning of the operation, after *all* typed
        // arguments have been validated. The private configuration is native.
        self.calls.set(self.calls.get() + 1);
        assert_eq!(self.root, Path::new("configured.pile"));
        output.text(format!(
            "id={}; dry_run={}; tags={:?}; limit={}; window={:?}",
            arguments.id, arguments.dry_run, arguments.tags, arguments.limit, arguments.window,
        ))
    }
}

fn request(server: &mut Server<'_>, text: &str) -> Option<serde_json::Value> {
    let response = server
        .dispatch(Bytes::from(text.as_bytes().to_vec()))
        .unwrap();
    response.map(|response| {
        canonical_json(Bytes::from(response.as_bytes().to_vec())).expect("valid response JSON");
        serde_json::from_str(&response).unwrap()
    })
}

fn initialize(server: &mut Server<'_>) {
    request(server, r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#).unwrap();
    assert!(request(
        server,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    )
    .is_none());
}

fn options() -> Options<'static> {
    Options {
        root: Path::new("configured.pile"),
        calls: Cell::new(0),
    }
}

#[test]
fn schema_retains_native_numbers_nested_objects_and_adapter_defaults() {
    let faculty = options();
    let mut server = Server::new(&[&faculty]).unwrap();
    initialize(&mut server);
    let response = request(
        &mut server,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    )
    .unwrap();
    let expected: serde_json::Value = serde_json::from_str(TOOLS[0].input_schema).unwrap();
    assert_eq!(response["result"]["tools"][0]["inputSchema"], expected);
    assert!(response["result"]["tools"][0]["inputSchema"]["properties"]
        .get("root")
        .is_none());
    assert_eq!(faculty.calls.get(), 0, "discovery performs no operation");
}

#[test]
fn wire_values_and_omissions_reach_typed_defaults_and_keep_array_duplicates() {
    let faculty = options();
    let mut server = Server::new(&[&faculty]).unwrap();
    initialize(&mut server);
    let omitted = request(&mut server, r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"options_show","arguments":{"id":"abcd"}}}"#).unwrap();
    let explicit = request(&mut server, r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"options_show","arguments":{"id":"abcd","dry_run":false,"tags":[],"limit":10,"window":null}}}"#).unwrap();
    for response in [omitted, explicit] {
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(
            response["result"]["content"][0]["text"],
            "id=abcd; dry_run=false; tags=[]; limit=10; window=None",
        );
    }
    let response = request(&mut server, r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"options_show","arguments":{"id":"abcd","dry_run":true,"tags":["first","first","second"],"limit":7,"window":{"start":-0.125,"end":2e1}}}}"#).unwrap();
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(
        response["result"]["content"][0]["text"],
        "id=abcd; dry_run=true; tags=[\"first\", \"first\", \"second\"]; limit=7; window=Some(Window { start: -0.125, end: 20.0 })",
    );
    assert_eq!(faculty.calls.get(), 3);
}

#[test]
fn wrong_types_duplicates_and_unknown_fields_fail_before_the_operation() {
    let faculty = options();
    let mut server = Server::new(&[&faculty]).unwrap();
    initialize(&mut server);
    for tail in [
        r#""dry_run":"true""#,
        r#""dry_run":[]"#,
        r#""tags":"tag""#,
        r#""tags":true"#,
        r#""tags":["valid",1]"#,
        r#""tags":[["nested"]]"#,
        r#""tags":null"#,
        r#""limit":"10""#,
        r#""limit":false"#,
        r#""limit":-1"#,
        r#""limit":1.5"#,
        r#""limit":4294967296"#,
        r#""tags":["first"],"tags":["second"]"#,
        r#""tags":["first"],"\u0074ags":["second"]"#,
        r#""window":[]"#,
        r#""window":[0,1]"#,
        r#""window":{"start":0}"#,
        r#""window":{"start":"0","end":1}"#,
        r#""window":{"start":0,"end":1,"unknown":2}"#,
        r#""window":{"start":0,"end":1,"start":2}"#,
        r#""window":{"start":0,"end":1,"\u0073tart":2}"#,
        r#""root":"wrong""#,
        r#""key":false"#,
        r#""unknown":[]"#,
    ] {
        let text = format!(
            r#"{{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{{"name":"options_show","arguments":{{"id":"abcd",{tail}}}}}}}"#,
        );
        let response = request(&mut server, &text).unwrap();
        assert_eq!(response["error"]["code"], -32602, "{tail}: {response}");
        assert!(response.get("result").is_none());
    }
    assert_eq!(faculty.calls.get(), 0);
}

#[test]
fn missing_required_arguments_and_call_notifications_do_not_run_operations() {
    let faculty = options();
    let mut server = Server::new(&[&faculty]).unwrap();
    initialize(&mut server);
    let response = request(
        &mut server,
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"options_show"}}"#,
    )
    .unwrap();
    assert_eq!(response["error"]["code"], -32602);
    assert!(request(&mut server, r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"options_show","arguments":{"id":"abcd","limit":7}}}"#).is_none());
    assert_eq!(faculty.calls.get(), 0);
}

#[test]
fn decoding_exposes_a_typed_marker_and_validates_standalone_input() {
    for input in [
        r#"{"id":"one","id":"two"}"#,
        r#"{"id":"one"} trailing"#,
        r#"{"id":"one","limit":"two"}"#,
    ] {
        let error = decode_arguments::<OptionsArguments>(Bytes::from(input.as_bytes().to_vec()))
            .context("adapter context")
            .unwrap_err();
        assert!(error.is::<InvalidArguments>(), "{error:#}");
    }
}
