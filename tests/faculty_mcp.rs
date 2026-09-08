use std::cell::Cell;
use std::io::{BufReader, Cursor, Write};
use std::process::{Command, Stdio};

use anybytes::Bytes;
use anyhow::{bail, Context, Result};
use faculties::archive_source::canonical_json;
use faculties::mcp::{decode_arguments, Faculty, Limits, Server, Tool};
use faculties::out::Out;
use serde::Deserialize;

const EMPTY_SCHEMA: &str = r#"{"type":"object","properties":{},"additionalProperties":false}"#;

#[test]
fn direct_adapter_decoding_requires_an_object_without_erasing_duplicate_fields() {
    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    struct Arguments {
        #[serde(default)]
        evaluate: bool,
    }
    for raw in [
        "[]",
        "[true]",
        "null",
        "true",
        "0",
        "\"text\"",
        " ",
        r#"{"evaluate":true,"evaluate":false}"#,
    ] {
        let error = decode_arguments::<Arguments>(raw.to_owned().into()).unwrap_err();
        assert!(
            error
                .downcast_ref::<faculties::mcp::InvalidArguments>()
                .is_some(),
            "{error:#}"
        );
    }
    assert!(
        !decode_arguments::<Arguments>(" \n\t{}\r ".to_owned().into())
            .unwrap()
            .evaluate
    );
    assert!(
        decode_arguments::<Arguments>(r#"{"evaluate":true}"#.to_owned().into())
            .unwrap()
            .evaluate
    );
}

static TOOLS: &[Tool] = &[
    Tool {
        name: "sample_mixed",
        description: "Ordered native media",
        input_schema: r#"{
            "type":"object",
            "properties":{"label":{"type":"string","description":"A text label"}},
            "required":["label"],
            "additionalProperties":false
        }"#,
    },
    Tool {
        name: "sample_empty",
        description: "No emissions",
        input_schema: EMPTY_SCHEMA,
    },
    Tool {
        name: "sample_fail",
        description: "Partial failure",
        input_schema: EMPTY_SCHEMA,
    },
    Tool {
        name: "sample_large",
        description: "Output limit",
        input_schema: EMPTY_SCHEMA,
    },
    Tool {
        name: "sample_media_limit",
        description: "Media limit",
        input_schema: EMPTY_SCHEMA,
    },
    Tool {
        name: "sample_ignore_limit",
        description: "Ignored sink failure",
        input_schema: EMPTY_SCHEMA,
    },
    Tool {
        name: "sample_blob",
        description: "Exact binary export",
        input_schema: EMPTY_SCHEMA,
    },
    Tool {
        name: "sample_blob_limit",
        description: "Binary export limit",
        input_schema: EMPTY_SCHEMA,
    },
    Tool {
        name: "sample_blob_metadata_limit",
        description: "Binary metadata limit",
        input_schema: EMPTY_SCHEMA,
    },
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LabelArguments {
    label: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyArguments {}

struct Sample {
    pile: &'static str,
    key: &'static str,
}

impl Faculty for Sample {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }

    fn call(&self, name: &str, arguments: Bytes, output: &mut Out<'_>) -> Result<()> {
        assert_eq!(self.pile, "configured.pile");
        assert_eq!(self.key, "configured.key");
        if name == "sample_mixed" {
            let arguments: LabelArguments =
                decode_arguments(arguments).context("decode the sample label")?;
            output.line(arguments.label)?;
            output.image(vec![0_u8, 255], "image/png")?;
            output.text("between")?;
            output.audio(vec![1_u8, 2, 3], "audio/wav")?;
            return output.text("");
        }
        let _: EmptyArguments = decode_arguments(arguments)?;
        match name {
            "sample_empty" => {}
            "sample_fail" => {
                output.text("accepted before failure")?;
                bail!("native failure after output");
            }
            "sample_large" => {
                output.text("accepted before limit")?;
                output.text("\u{0001}".repeat(10_000))?;
            }
            "sample_media_limit" => {
                output.text("accepted before limit")?;
                output.image(vec![0_u8; 10_000], "image/png")?;
            }
            "sample_ignore_limit" => {
                output.text("accepted before limit")?;
                let _ = output.text("x".repeat(10_000));
                let _ = output.text("must not leak after rejection");
            }
            "sample_blob" => output.blob(
                vec![0_u8, 0xff, b'\n'],
                "application/octet-stream",
                "files:test-export",
            )?,
            "sample_blob_limit" => {
                output.text("accepted before limit")?;
                output.blob(
                    vec![0_u8; 10_000],
                    "application/octet-stream",
                    "files:test-export",
                )?;
            }
            "sample_blob_metadata_limit" => {
                output.text("accepted before limit")?;
                output.blob(
                    Vec::<u8>::new(),
                    "application/octet-stream",
                    format!("files:{}", "a".repeat(10_000)),
                )?;
            }
            other => panic!("unexpected test tool {other}"),
        }
        Ok(())
    }
}

static SAMPLE: Sample = Sample {
    pile: "configured.pile",
    key: "configured.key",
};

fn registrations() -> [&'static dyn Faculty; 1] {
    [&SAMPLE]
}

fn dispatch(server: &mut Server<'_>, request: &str) -> Option<String> {
    let response = server
        .dispatch(Bytes::from(request.as_bytes().to_vec()))
        .unwrap();
    if let Some(response) = &response {
        canonical_json(Bytes::from(response.as_bytes().to_vec())).expect("valid response JSON");
        assert!(
            !response.contains('\n'),
            "wire frames have no embedded newlines"
        );
    }
    response
}

fn initialize(server: &mut Server<'_>) {
    let response = dispatch(server, r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#).unwrap();
    assert!(response.contains(r#""protocolVersion":"2025-06-18""#));
    assert!(response.contains(r#""capabilities":{"tools":{}}"#));
    assert!(!response.contains("listChanged"));
    assert!(dispatch(
        server,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
    )
    .is_none());
}

#[test]
fn executable_stdio_exposes_native_faculties_without_opening_the_pile_or_drive() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("not-opened.pile");
    let mut child = Command::new(env!("CARGO_BIN_EXE_faculties"))
        .args(["mcp", "--pile"])
        .arg(&pile)
        .env("DRIVE_ENDPOINT", "invalid-and-must-not-be-consulted")
        .env_remove("TRIBLESPACE_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    for request in [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#,
    ] {
        writeln!(input, "{request}").unwrap();
    }
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert!(output.stderr.is_empty());
    assert!(
        !pile.exists(),
        "discovery must not open the configured pile"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let responses: Vec<_> = stdout.lines().collect();
    assert_eq!(responses.len(), 3, "stdout contains only RPC responses");
    for response in &responses {
        canonical_json(Bytes::from(response.as_bytes().to_vec())).unwrap();
    }
    assert!(responses[1].contains(r#""name":"atlas_list""#));
    assert!(responses[1].contains(r#""name":"atlas_show""#));
    assert!(responses[1].contains(r#""name":"files_get""#));
    assert!(responses[1].contains(r#""name":"files_view""#));
    assert!(!responses[1].contains(r#""name":"files_read""#));
    let discovery: serde_json::Value = serde_json::from_str(responses[1]).unwrap();
    let tools = discovery["result"]["tools"].as_array().unwrap();
    let names: std::collections::BTreeSet<_> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names.len(),
        tools.len(),
        "one unambiguous aggregate registry"
    );
    for name in [
        "compass_add",
        "compass_list",
        "compass_move",
        "compass_note",
        "compass_show",
        "compass_prioritize",
        "compass_deprioritize",
        "compass_resolve",
        "message_send",
        "message_list",
        "message_ack",
        "message_ack_all",
        "wiki_create",
        "wiki_edit",
        "wiki_show",
        "wiki_export",
        "wiki_search",
        "wiki_history",
        "wiki_archive",
        "wiki_restore",
        "wiki_revert",
        "archive_import",
        "body_capture",
        "bootstrap_import",
        "cognition_check",
        "decide_propose",
        "discord_read",
        "duplex_status",
        "gauge_health",
        "habit_list",
        "headspace_list",
        "hear_once",
        "imagine_generate",
        "linkedin_import",
        "mail_list",
        "memory_context",
        "orient_poll",
        "patience_extend",
        "planner_list",
        "posture_scan",
        "reason_record",
        "relations_list",
        "secrets_list",
        "status_list",
        "teams_read",
        "triage_scan",
        "viewer_capture",
        "voice_synthesize",
        "web_search",
    ] {
        assert!(names.contains(name), "missing native tool {name}");
    }
    for tool in tools {
        let properties = tool["inputSchema"]["properties"].as_object().unwrap();
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        for ambient in ["pile", "key", "path", "dir", "scope", "branch"] {
            assert!(
                !properties.contains_key(ambient),
                "{} exposes {ambient}",
                tool["name"]
            );
        }
    }
    assert!(!responses[1].contains("\"pile\":"));
    assert!(!responses[1].contains("\"key\":"));
    assert_eq!(responses[2], r#"{"jsonrpc":"2.0","id":3,"result":{}}"#);
}

#[test]
fn handshake_gates_calls_and_negotiates_supported_version() {
    let registrations = registrations();
    let mut server = Server::new(&registrations).unwrap();
    assert!(dispatch(
        &mut server,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
    )
    .is_none());
    let early = dispatch(
        &mut server,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sample_empty"}}"#,
    )
    .unwrap();
    assert!(early.contains(r#""code":-32000"#));
    assert!(dispatch(
        &mut server,
        r#"{"jsonrpc":"2.0","id":"ping","method":"ping"}"#
    )
    .unwrap()
    .contains(r#""result":{}"#));
    let response = dispatch(&mut server, r#"{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"future-version","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#).unwrap();
    assert!(response.contains(r#""protocolVersion":"2025-06-18""#));
    let before_notification = dispatch(
        &mut server,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/list"}"#,
    )
    .unwrap();
    assert!(before_notification.contains(r#""code":-32000"#));
    dispatch(
        &mut server,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    let empty = dispatch(
        &mut server,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"sample_empty"}}"#,
    )
    .unwrap();
    assert!(empty.contains(r#""content":[],"isError":false"#));
    let repeated = dispatch(
        &mut server,
        r#"{"jsonrpc":"2.0","id":6,"method":"initialize","params":{}}"#,
    )
    .unwrap();
    assert!(repeated.contains(r#""code":-32600"#));
}

#[test]
fn list_uses_explicit_mcp_schemas_and_hides_launcher_configuration() {
    let registrations = registrations();
    let mut server = Server::new(&registrations).unwrap();
    initialize(&mut server);
    let response = dispatch(
        &mut server,
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}"#,
    )
    .unwrap();
    for tool in TOOLS {
        assert!(response.contains(&format!(r#""name":"{}""#, tool.name)));
    }
    let decoded: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(
        decoded["result"]["tools"][0]["inputSchema"]["properties"]["label"],
        serde_json::json!({"type":"string","description":"A text label"}),
    );
    assert!(response.contains(r#""required":["label"]"#));
    assert!(response.contains(r#""additionalProperties":false"#));
    assert!(!response.contains("pile"));
    assert!(!response.contains("key"));
    assert!(!response.contains("outputSchema"));
}

#[test]
fn native_parts_preserve_order_text_and_binary_content() {
    let registrations = registrations();
    let mut server = Server::new(&registrations).unwrap();
    initialize(&mut server);
    let response = dispatch(&mut server, r#"{"jsonrpc":"2.0","id":"quote\"id","method":"tools/call","params":{"name":"sample_mixed","arguments":{"label":"first\nsecond \"quoted\""}}}"#).unwrap();
    assert!(response.contains(r#""id":"quote\"id""#));
    assert!(response.contains(r#""content":[{"type":"text","text":"first\nsecond \"quoted\"\n"},{"type":"image","data":"AP8=","mimeType":"image/png"},{"type":"text","text":"between"},{"type":"audio","data":"AQID","mimeType":"audio/wav"},{"type":"text","text":""}],"isError":false"#), "{response}");
}

#[test]
fn blob_exports_are_embedded_binary_resources_not_text() {
    let registrations = registrations();
    let mut server = Server::new(&registrations).unwrap();
    initialize(&mut server);
    let response = dispatch(
        &mut server,
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"sample_blob"}}"#,
    )
    .unwrap();
    assert!(response.contains(r#""content":[{"type":"resource","resource":{"uri":"files:test-export","mimeType":"application/octet-stream","blob":"AP8K"}}],"isError":false"#), "{response}");
}

#[test]
fn tool_errors_preserve_partial_content_but_validation_is_protocol_error() {
    let registrations = registrations();
    let mut server = Server::new(&registrations).unwrap();
    initialize(&mut server);
    let response = dispatch(
        &mut server,
        r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"sample_fail"}}"#,
    )
    .unwrap();
    assert!(response.contains(r#""isError":true"#));
    assert!(response.contains("accepted before failure"));
    assert!(response.contains("native failure after output"));
    assert!(!response.contains(r#""error":"#));
    for args in [
        r#"{"label":1}"#,
        r#"{"label":true}"#,
        r#"{"label":null}"#,
        r#"{"label":[]}"#,
        r#"{"label":{}}"#,
        r#"{"label":"ok","pile":"elsewhere"}"#,
        r#"{"label":"ok","key":"elsewhere"}"#,
        r#"{"label":"ok","other":"value"}"#,
        r#"{"label":"ok","label":"again"}"#,
        r#"{"label":"ok","\u006cabel":"again"}"#,
        "{}",
        "[]",
        "null",
        "1",
    ] {
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{{"name":"sample_mixed","arguments":{args}}}}}"#
        );
        let response = dispatch(&mut server, &request).unwrap();
        assert!(response.contains(r#""code":-32602"#), "{response}");
        assert!(!response.contains("content"));
    }
}

struct NeverCall;

impl Faculty for NeverCall {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }

    fn call(&self, _: &str, _: Bytes, _: &mut Out<'_>) -> Result<()> {
        panic!("a notification invoked a write-capable native handler");
    }
}

#[test]
fn notifications_and_unsolicited_responses_never_invoke_or_reply() {
    let mut server = Server::new(&[&NeverCall]).unwrap();
    initialize(&mut server);
    for request in [
        r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"sample_empty"}}"#,
        r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"sample_mixed","arguments":{"label":false}}}"#,
        r#"{"jsonrpc":"2.0","method":"unknown"}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
    ] {
        assert!(dispatch(&mut server, request).is_none());
    }
}

#[test]
fn request_ids_are_lossless_and_bad_envelopes_have_protocol_errors() {
    let registrations = registrations();
    let mut server = Server::new(&registrations).unwrap();
    for id in [
        "184467440737095516160000000001",
        "-184467440737095516160000000001",
        r#""\ud83d\ude00""#,
    ] {
        let request = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#);
        assert!(dispatch(&mut server, &request)
            .unwrap()
            .contains(&format!(r#""id":{id},"#)));
    }
    for id in ["null", "false", "1.25", "1e2", "[]", "{}"] {
        let request = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#);
        assert!(dispatch(&mut server, &request)
            .unwrap()
            .contains(r#""code":-32600"#));
    }
    for request in [
        r#"{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}"#,
        r#"{"jsonrpc":"wrong","id":1,"method":"ping"}"#,
        "[]",
        "{}",
    ] {
        assert!(dispatch(&mut server, request)
            .unwrap()
            .contains(r#""code":-32600"#));
    }
    for request in [
        "{",
        "{} trailing",
        r#"{"jsonrpc":"2.0","id":01,"method":"ping"}"#,
    ] {
        assert!(dispatch(&mut server, request)
            .unwrap()
            .contains(r#""code":-32700"#));
    }
    assert!(dispatch(
        &mut server,
        r#"{"jsonrpc":"2.0","id":2,"method":"unknown"}"#
    )
    .unwrap()
    .contains(r#""code":-32601"#));
}

#[test]
fn output_limits_reject_expansion_preserve_prior_parts_and_are_sticky() {
    let registrations = registrations();
    let mut server = Server::with_limits(
        &registrations,
        Limits {
            response_bytes: 4096,
            ..Limits::default()
        },
    )
    .unwrap();
    initialize(&mut server);
    for name in [
        "sample_large",
        "sample_media_limit",
        "sample_ignore_limit",
        "sample_blob_limit",
        "sample_blob_metadata_limit",
    ] {
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{{"name":"{name}"}}}}"#
        );
        let response = dispatch(&mut server, &request).unwrap();
        assert!(response.len() <= 4096);
        assert!(response.contains("accepted before limit"));
        assert!(response.contains("response budget"));
        assert!(response.contains(r#""isError":true"#));
        assert!(!response.contains("must not leak"));
    }
}

#[test]
fn frame_and_depth_limits_do_not_invoke_handlers() {
    let registrations = registrations();
    let mut server = Server::with_limits(
        &registrations,
        Limits {
            request_bytes: 64,
            ..Limits::default()
        },
    )
    .unwrap();
    let input = Cursor::new(vec![b' '; 65]);
    assert!(server
        .serve(BufReader::with_capacity(8, input), Vec::new())
        .is_err());
    assert!(server.dispatch(Bytes::from(vec![b' '; 65])).is_err());
    let mut server = Server::new(&registrations).unwrap();
    let deep = format!("{}0{}", "[".repeat(65), "]".repeat(65));
    assert!(dispatch(&mut server, &deep).unwrap().contains("nesting"));
    assert!(server
        .serve(
            Cursor::new(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}"),
            Vec::new()
        )
        .is_err());
}

#[test]
fn stdio_writes_only_delimited_responses_and_handles_crlf() {
    let registrations = registrations();
    let mut server = Server::new(&registrations).unwrap();
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"sample_empty\"}}\n{\"jsonrpc\":\"2.0\",\"id\":\"last\",\"method\":\"ping\"}\n";
    let mut output = Vec::new();
    server
        .serve(BufReader::with_capacity(7, Cursor::new(input)), &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert_eq!(output.lines().count(), 2);
    for line in output.lines() {
        canonical_json(Bytes::from(line.as_bytes().to_vec())).unwrap();
    }
    assert!(output.ends_with('\n'));
}

#[test]
fn duplicate_native_tool_names_are_rejected() {
    let mut registrations = Vec::from(registrations());
    registrations.extend(self::registrations());
    assert!(Server::new(&registrations).is_err());
}

struct Declared {
    tools: Vec<Tool>,
    snapshots: Cell<usize>,
}

impl Faculty for Declared {
    fn tools(&self) -> &[Tool] {
        self.snapshots.set(self.snapshots.get() + 1);
        &self.tools
    }

    fn call(&self, name: &str, arguments: Bytes, output: &mut Out<'_>) -> Result<()> {
        let _: EmptyArguments = decode_arguments(arguments)?;
        output.text(format!("declared faculty called: {name}"))
    }
}

#[test]
fn registration_snapshots_schemas_once_and_routes_to_each_faculty() {
    let declared = Declared {
        tools: vec![Tool {
            name: "custom.name",
            description: "An independent MCP name\nand description",
            input_schema: EMPTY_SCHEMA,
        }],
        snapshots: Cell::new(0),
    };
    let mut server = Server::new(&[&SAMPLE, &declared]).unwrap();
    initialize(&mut server);
    for _ in 0..2 {
        let response = dispatch(
            &mut server,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        )
        .unwrap();
        assert!(response.contains("sample_mixed"));
        assert!(response.contains("custom.name"));
    }
    let response = dispatch(
        &mut server,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"custom.name"}}"#,
    )
    .unwrap();
    assert!(response.contains("declared faculty called: custom.name"));
    let response = dispatch(
        &mut server,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"sample_empty"}}"#,
    )
    .unwrap();
    assert!(response.contains(r#""content":[],"isError":false"#));
    assert_eq!(declared.snapshots.get(), 1);
}

#[test]
fn invalid_schema_shapes_and_intrafaculty_duplicate_names_are_rejected() {
    for schema in [
        "{",
        "{} trailing",
        "true",
        "null",
        "[]",
        "{}",
        r#"{"type":"array"}"#,
        r#"{"type":["object","null"]}"#,
    ] {
        let declared = Declared {
            tools: vec![Tool {
                name: "invalid_schema",
                description: "A broken descriptor",
                input_schema: schema,
            }],
            snapshots: Cell::new(0),
        };
        assert!(Server::new(&[&declared]).is_err(), "{schema}");
    }
    let declared = Declared {
        tools: vec![
            Tool {
                name: "duplicate",
                description: "First declaration",
                input_schema: EMPTY_SCHEMA,
            },
            Tool {
                name: "duplicate",
                description: "Second declaration",
                input_schema: EMPTY_SCHEMA,
            },
        ],
        snapshots: Cell::new(0),
    };
    assert!(Server::new(&[&declared]).is_err());
}
