use std::io::{BufReader, Cursor, Write};
use std::process::{Command, Stdio};

use anybytes::Bytes;
use anyhow::{bail, Result};
use faculties::archive_source::canonical_json;
use faculties::mcp::{Limits, Registration, Server};
use faculties::out::Out;
use faculties::spec::{Arguments, Invocation, Param, Spec, Verb};

static SPEC: Spec = Spec {
    name: "sample",
    about: "Native test faculty",
    version: None,
    shared: &[
        Param::caller("pile", "Configured pile").ambient(),
        Param::caller("key", "Configured key").ambient().optional(),
    ],
    verbs: &[
        Verb {
            name: "mixed",
            about: "Ordered native media",
            params: &[Param::caller("label", "A text label")],
        },
        Verb {
            name: "empty",
            about: "No emissions",
            params: &[],
        },
        Verb {
            name: "fail",
            about: "Partial failure",
            params: &[],
        },
        Verb {
            name: "large",
            about: "Output limit",
            params: &[],
        },
        Verb {
            name: "media_limit",
            about: "Media limit",
            params: &[],
        },
        Verb {
            name: "ignore_limit",
            about: "Ignored sink failure",
            params: &[],
        },
    ],
};

fn execute(invocation: &Invocation, output: &mut Out<'_>) -> Result<()> {
    assert_eq!(invocation.require("pile")?, "configured.pile");
    assert_eq!(invocation.get("key"), Some("configured.key"));
    match invocation.verb().name {
        "mixed" => {
            output.line(invocation.require("label")?)?;
            output.image(vec![0_u8, 255], "image/png")?;
            output.text("between")?;
            output.audio(vec![1_u8, 2, 3], "audio/wav")?;
            output.text("")?;
        }
        "empty" => {}
        "fail" => {
            output.text("accepted before failure")?;
            bail!("native failure after output");
        }
        "large" => {
            output.text("accepted before limit")?;
            output.text("\u{0001}".repeat(10_000))?;
        }
        "media_limit" => {
            output.text("accepted before limit")?;
            output.image(vec![0_u8; 10_000], "image/png")?;
        }
        "ignore_limit" => {
            output.text("accepted before limit")?;
            let _ = output.text("x".repeat(10_000));
            let _ = output.text("must not leak after rejection");
        }
        other => panic!("unexpected test verb {other}"),
    }
    Ok(())
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
fn executable_stdio_exposes_only_atlas_without_opening_the_pile_or_drive() {
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
    assert_eq!(responses[1].matches("\"inputSchema\"").count(), 2);
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
fn list_is_derived_from_spec_and_hides_ambient_parameters() {
    let registrations = registrations();
    let mut server = Server::new(&registrations).unwrap();
    initialize(&mut server);
    let response = dispatch(
        &mut server,
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}"#,
    )
    .unwrap();
    for tool in SPEC.mcp_tools() {
        assert!(response.contains(&format!(r#""name":"{}""#, tool.name)));
    }
    assert!(response.contains(r#""label":{"type":"string","description":"A text label"}"#));
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
        "{}",
    ] {
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{{"name":"sample_mixed","arguments":{args}}}}}"#
        );
        let response = dispatch(&mut server, &request).unwrap();
        assert!(response.contains(r#""code":-32602"#), "{response}");
        assert!(!response.contains("content"));
    }
}

#[test]
fn invalid_ambient_origins_are_rejected_before_handler() {
    let registrations = [Registration {
        spec: &SPEC,
        invoke: |_, _| panic!("invalid ambient arguments reached handler"),
        ambient: Arguments::new()
            .with("pile", "configured.pile")
            .with("label", "wrong origin"),
    }];
    let mut server = Server::new(&registrations).unwrap();
    initialize(&mut server);
    let response = dispatch(&mut server, r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"sample_mixed","arguments":{"label":"caller"}}}"#).unwrap();
    assert!(response.contains(r#""code":-32602"#));
}

#[test]
fn notifications_and_unsolicited_responses_never_invoke_or_reply() {
    let registrations = [Registration {
        spec: &SPEC,
        invoke: |_, _| panic!("a notification invoked a write-capable native handler"),
        ambient: Arguments::new().with("pile", "configured.pile"),
    }];
    let mut server = Server::new(&registrations).unwrap();
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
    for name in ["sample_large", "sample_media_limit", "sample_ignore_limit"] {
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
