//! Real loopback transport checks. These fixtures have no pile, model, shell,
//! ambient credentials, or public listener; HTTP and stdio use the same native
//! non-Sync adapter. Blocking work is controlled with bounded channels.

use std::cell::Cell;
use std::io::{BufRead, BufReader, Cursor, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anybytes::Bytes;
use anyhow::{Context, Result};
use faculties::mcp::http::{BearerToken, Config, Endpoint};
use faculties::mcp::{decode_arguments, Faculty, Server, Tool, PROTOCOL_VERSION};
use faculties::out::Out;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::{HeaderValue, AUTHORIZATION, ORIGIN};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::{json, Value};

const TOKEN: &str = "http-integration-test-only-0123456789abcdef";
const ORIGIN_VALUE: &str = "https://mcp.example.test";
const SESSION_HEADER: &str = "mcp-session-id";
const VERSION_HEADER: &str = "mcp-protocol-version";
const ACCEPT: &str = "application/json, text/event-stream";
const WAIT: Duration = Duration::from_secs(5);
const EMPTY_SCHEMA: &str = r#"{"type":"object","properties":{},"additionalProperties":false}"#;
const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"loopback-test","version":"1"}}}"#;
const INITIALIZED: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const PING: &str = r#"{"jsonrpc":"2.0","id":9,"method":"ping"}"#;
const LIST: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;

static TOOLS: &[Tool] = &[
    Tool {
        name: "test_mixed",
        description: "Ordered text, image, audio, and exact binary export",
        input_schema: EMPTY_SCHEMA,
    },
    Tool {
        name: "test_block",
        description: "A channel-controlled finite blocking operation",
        input_schema: EMPTY_SCHEMA,
    },
    Tool {
        name: "test_large",
        description: "An oversized native emission after accepted text",
        input_schema: EMPTY_SCHEMA,
    },
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyArguments {}

struct Blocking {
    started: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
    completed: mpsc::Sender<()>,
}

#[derive(Default)]
struct Fixture {
    // Cell and the optional Receiver deliberately make this adapter non-Sync.
    local_calls: Cell<usize>,
    calls: Arc<AtomicUsize>,
    blocking: Option<Blocking>,
}

impl Faculty for Fixture {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }

    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        let _: EmptyArguments = decode_arguments(arguments)?;
        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "native adapters must run outside the HTTP I/O runtime"
        );
        self.local_calls.set(self.local_calls.get() + 1);
        self.calls.fetch_add(1, Ordering::SeqCst);
        match name {
            "test_mixed" => {
                out.text("first\n\"literal\" @file")?;
                out.image(vec![0_u8, 255], "image/png")?;
                out.text("between")?;
                out.audio(vec![1_u8, 2, 3], "audio/wav")?;
                out.blob(
                    vec![0_u8, 255, b'\n'],
                    "application/octet-stream",
                    "files:test-exact-export",
                )?;
                out.text("")?;
            }
            "test_block" => {
                let block = self
                    .blocking
                    .as_ref()
                    .context("blocking fixture not configured")?;
                block.started.send(())?;
                block
                    .release
                    .recv_timeout(WAIT)
                    .context("release blocking fixture")?;
                out.text("completed exactly once")?;
                block.completed.send(())?;
            }
            "test_large" => {
                out.text("accepted before limit")?;
                out.image(vec![0_u8; 10_000], "image/png")?;
            }
            other => anyhow::bail!("unknown synthetic tool {other}"),
        }
        Ok(())
    }
}

struct BlockingControl {
    started: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
    completed: mpsc::Receiver<()>,
    calls: Arc<AtomicUsize>,
}

fn blocking_fixture() -> (Fixture, BlockingControl) {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (completed_tx, completed_rx) = mpsc::channel();
    let calls = Arc::new(AtomicUsize::new(0));
    (
        Fixture {
            calls: calls.clone(),
            blocking: Some(Blocking {
                started: started_tx,
                release: release_rx,
                completed: completed_tx,
            }),
            ..Fixture::default()
        },
        BlockingControl {
            started: started_rx,
            release: release_tx,
            completed: completed_rx,
            calls,
        },
    )
}

fn config() -> Config {
    Config::new(
        "127.0.0.1:0".parse().unwrap(),
        BearerToken::new(TOKEN).unwrap(),
    )
}

struct TestEndpoint {
    addr: SocketAddr,
    url: String,
    client: Client,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<JoinHandle<Result<()>>>,
}

impl TestEndpoint {
    fn new(config: Config, faculty: Fixture) -> Self {
        let endpoint = Endpoint::bind(config).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let worker = thread::spawn(move || {
            endpoint.serve_until(&[&faculty], async move {
                let _ = stopped.await;
            })
        });
        Self {
            addr,
            url: format!("http://{addr}/"),
            client: Client::builder()
                .no_proxy()
                .timeout(WAIT)
                .pool_max_idle_per_host(0)
                .build()
                .unwrap(),
            shutdown: Some(shutdown),
            worker: Some(worker),
        }
    }

    fn request(&self, method: Method, session: Option<&str>) -> RequestBuilder {
        let mut request = self
            .client
            .request(method, &self.url)
            .bearer_auth(TOKEN)
            .header("accept", ACCEPT)
            .header(VERSION_HEADER, PROTOCOL_VERSION);
        if let Some(session) = session {
            request = request.header(SESSION_HEADER, session);
        }
        request
    }

    fn post(&self, session: Option<&str>, body: &str) -> Response {
        self.request(Method::POST, session)
            .header("content-type", "application/json")
            .body(body.to_owned())
            .send()
            .unwrap()
    }

    fn initialize(&self) -> String {
        let response = self.post(None, INITIALIZE);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let session = response.headers()[SESSION_HEADER]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(!session.is_empty());
        assert!(session.bytes().all(|byte| (0x21..=0x7e).contains(&byte)));
        let body: Value = response.json().unwrap();
        assert_eq!(body["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(body["result"]["capabilities"], json!({"tools": {}}));
        session
    }

    fn ready(&self) -> String {
        let session = self.initialize();
        let response = self.post(Some(&session), INITIALIZED);
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.text().unwrap(), "");
        session
    }

    fn connect_raw(&self) -> TcpStream {
        let stream = TcpStream::connect_timeout(&self.addr, WAIT).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        stream.set_write_timeout(Some(WAIT)).unwrap();
        stream
    }
}

impl Drop for TestEndpoint {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result
                    .expect("HTTP worker panicked")
                    .expect("HTTP worker failed");
            }
        }
    }
}

fn call(name: &str) -> String {
    json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
        "name": name, "arguments": {}
    }})
    .to_string()
}

fn rpc(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(response.headers()["cache-control"], "no-store");
    response.json().unwrap()
}

fn raw_post(stream: &mut TcpStream, addr: SocketAddr, session: &str, body: &str) {
    write!(stream,
        "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {TOKEN}\r\nAccept: {ACCEPT}\r\nContent-Type: application/json\r\nMCP-Protocol-Version: {PROTOCOL_VERSION}\r\nMcp-Session-Id: {session}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    ).unwrap();
    stream.flush().unwrap();
}

#[test]
fn http_native_media_and_discovery_match_stdio_without_reencoding_the_data_model() {
    let calls = Arc::new(AtomicUsize::new(0));
    let endpoint = TestEndpoint::new(
        config(),
        Fixture {
            calls: calls.clone(),
            ..Fixture::default()
        },
    );
    let session = endpoint.ready();
    let tools = rpc(endpoint.post(Some(&session), LIST));
    let names: Vec<_> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["test_mixed", "test_block", "test_large"]);
    let body = call("test_mixed");
    let result = rpc(endpoint.post(Some(&session), &body));
    assert_eq!(
        result["result"],
        json!({"isError": false, "content": [
            {"type": "text", "text": "first\n\"literal\" @file"},
            {"type": "image", "data": "AP8=", "mimeType": "image/png"},
            {"type": "text", "text": "between"},
            {"type": "audio", "data": "AQID", "mimeType": "audio/wav"},
            {"type": "resource", "resource": {"uri": "files:test-exact-export", "mimeType": "application/octet-stream", "blob": "AP8K"}},
            {"type": "text", "text": ""}
        ]})
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let native = Fixture::default();
    let mut server = Server::new(&[&native]).unwrap();
    let input = format!("{INITIALIZE}\n{INITIALIZED}\n{body}\n");
    let mut output = Vec::new();
    server.serve(Cursor::new(input), &mut output).unwrap();
    let frames: Vec<Value> = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[1], result);
}

#[test]
fn http_accepts_pretty_printed_json_not_just_stdio_line_frames() {
    let endpoint = TestEndpoint::new(config(), Fixture::default());
    let body =
        serde_json::to_string_pretty(&serde_json::from_str::<Value>(INITIALIZE).unwrap()).unwrap();
    assert!(body.contains('\n'));
    let response = endpoint.post(None, &body);
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(SESSION_HEADER));
    assert_eq!(
        response.json::<Value>().unwrap()["result"]["protocolVersion"],
        PROTOCOL_VERSION
    );
}

#[test]
fn notifications_and_unsolicited_responses_are_accepted_without_invoking_tools() {
    let calls = Arc::new(AtomicUsize::new(0));
    let endpoint = TestEndpoint::new(
        config(),
        Fixture {
            calls: calls.clone(),
            ..Fixture::default()
        },
    );
    let session = endpoint.ready();
    for body in [
        r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"test_mixed","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}"#,
        r#"{"jsonrpc":"2.0","id":99,"result":{}}"#,
        r#"{"jsonrpc":"2.0","method":"unknown/notification"}"#,
    ] {
        let response = endpoint.post(Some(&session), body);
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.text().unwrap(), "");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        rpc(endpoint.post(Some(&session), PING))["result"],
        json!({})
    );
}

#[test]
fn readiness_and_deletion_are_per_session_and_get_does_not_advertise_sse() {
    let endpoint = TestEndpoint::new(config(), Fixture::default());
    let first = endpoint.initialize();
    let second = endpoint.initialize();
    assert_ne!(first, second);
    assert_eq!(
        rpc(endpoint.post(Some(&first), LIST))["error"]["code"],
        -32000
    );
    let duplicate_notification =
        r#"{"jsonrpc":"2.0","jsonrpc":"2.0","method":"notifications/initialized"}"#;
    assert_eq!(
        endpoint.post(Some(&first), duplicate_notification).status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        rpc(endpoint.post(Some(&first), LIST))["error"]["code"],
        -32000
    );
    assert_eq!(
        endpoint.post(Some(&first), INITIALIZED).status(),
        StatusCode::ACCEPTED
    );
    assert!(rpc(endpoint.post(Some(&first), LIST))["result"]["tools"].is_array());
    assert_eq!(
        rpc(endpoint.post(Some(&second), LIST))["error"]["code"],
        -32000
    );
    assert_eq!(
        rpc(endpoint.post(Some(&first), INITIALIZE))["error"]["code"],
        -32600
    );

    let get = endpoint.request(Method::GET, Some(&first)).send().unwrap();
    assert_eq!(get.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(get.headers()["allow"], "POST, DELETE");
    assert_eq!(get.headers()["cache-control"], "no-store");
    let deleted = endpoint
        .request(Method::DELETE, Some(&first))
        .send()
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    assert_eq!(deleted.text().unwrap(), "");
    assert_eq!(
        endpoint.post(Some(&first), PING).status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        endpoint
            .request(Method::DELETE, Some(&first))
            .send()
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        endpoint
            .request(Method::DELETE, None)
            .send()
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        endpoint.post(Some(&second), INITIALIZED).status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(rpc(endpoint.post(Some(&second), PING))["result"], json!({}));
    assert_eq!(
        endpoint.post(Some("not-a-session"), PING).status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(endpoint.post(None, LIST).status(), StatusCode::BAD_REQUEST);
}

#[test]
fn session_capacity_is_reclaimed_on_delete_and_idle_expiry() {
    let mut bounded = config();
    bounded.max_sessions = 1;
    bounded.session_idle_timeout = Duration::from_millis(250);
    let endpoint = TestEndpoint::new(bounded, Fixture::default());
    let first = endpoint.initialize();
    let full = endpoint.post(None, INITIALIZE);
    assert_eq!(full.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!full.headers().contains_key(SESSION_HEADER));
    assert_eq!(
        endpoint
            .request(Method::DELETE, Some(&first))
            .send()
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    let second = endpoint.initialize();
    assert_ne!(first, second);
    // This is the only clock-driven wait: comfortably beyond the explicit
    // short idle lease. All blocking-operation tests use channel handshakes.
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        endpoint.post(Some(&second), PING).status(),
        StatusCode::NOT_FOUND
    );
    let third = endpoint.initialize();
    assert_ne!(second, third);
}

#[test]
fn invalid_and_duplicate_initialization_never_consume_the_only_session_slot() {
    let mut bounded = config();
    bounded.max_sessions = 1;
    let endpoint = TestEndpoint::new(bounded, Fixture::default());
    for body in [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":1,"id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
    ] {
        let response = endpoint.post(None, body);
        assert_eq!(response.status(), StatusCode::OK, "{body}");
        assert!(!response.headers().contains_key(SESSION_HEADER));
        assert!(response.json::<Value>().unwrap()["error"]["code"].is_number());
    }
    let notification = INITIALIZE.replace(r#""id":1,"#, "");
    let response = endpoint.post(None, &notification);
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(!response.headers().contains_key(SESSION_HEADER));
    for body in ["{", "[]", INITIALIZED, PING] {
        let response = endpoint.post(None, body);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.headers().contains_key(SESSION_HEADER));
    }
    endpoint.ready();
}

#[test]
fn bearer_authentication_is_required_even_on_loopback_and_duplicate_auth_is_rejected() {
    let endpoint = TestEndpoint::new(config(), Fixture::default());
    for authorization in [None, Some("Bearer wrong"), Some("Basic irrelevant")] {
        let mut request = endpoint
            .client
            .post(&endpoint.url)
            .header("content-type", "application/json")
            .header("accept", ACCEPT)
            .body(INITIALIZE);
        if let Some(authorization) = authorization {
            request = request.header("authorization", authorization);
        }
        let response = request.send().unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()["www-authenticate"], "Bearer");
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(!response.text().unwrap().contains(TOKEN));
    }
    let mut duplicate = endpoint
        .request(Method::POST, None)
        .header("content-type", "application/json")
        .body(INITIALIZE)
        .build()
        .unwrap();
    duplicate.headers_mut().append(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {TOKEN}")).unwrap(),
    );
    assert_eq!(
        endpoint.client.execute(duplicate).unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    endpoint.ready();
}

#[test]
fn present_origin_requires_an_exact_allowlist_match_without_wildcards_or_duplicates() {
    let mut allowed = config();
    allowed.allowed_origins = vec![ORIGIN_VALUE.to_owned()];
    let endpoint = TestEndpoint::new(allowed, Fixture::default());
    for origin in [
        "null",
        "https://other.example.test",
        "https://mcp.example.test/",
        "http://mcp.example.test",
        "https://mcp.example.test.evil",
    ] {
        let response = endpoint
            .request(Method::POST, None)
            .header("origin", origin)
            .header("content-type", "application/json")
            .body(INITIALIZE)
            .send()
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{origin}");
        assert!(!response
            .headers()
            .contains_key("access-control-allow-origin"));
    }
    let mut duplicate = endpoint
        .request(Method::POST, None)
        .header("origin", ORIGIN_VALUE)
        .header("content-type", "application/json")
        .body(INITIALIZE)
        .build()
        .unwrap();
    duplicate
        .headers_mut()
        .append(ORIGIN, HeaderValue::from_static(ORIGIN_VALUE));
    assert_eq!(
        endpoint.client.execute(duplicate).unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let response = endpoint
        .request(Method::POST, None)
        .header("origin", ORIGIN_VALUE)
        .header("content-type", "application/json")
        .body(INITIALIZE)
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(SESSION_HEADER));
    assert!(!response
        .headers()
        .contains_key("access-control-allow-origin"));
    endpoint.ready(); // Absent Origin is a permitted server-to-server request.
}

#[test]
fn protocol_media_accept_and_header_shape_are_validated_before_dispatch() {
    let endpoint = TestEndpoint::new(config(), Fixture::default());
    let session = endpoint.ready();
    for (header, value, expected) in [
        (
            "content-type",
            "text/plain",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "content-encoding",
            "gzip",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        ("accept", "application/json", StatusCode::NOT_ACCEPTABLE),
        ("accept", "text/event-stream", StatusCode::NOT_ACCEPTABLE),
        ("accept", "*/*", StatusCode::NOT_ACCEPTABLE),
        (
            "accept",
            "application/json;q=0, text/event-stream",
            StatusCode::NOT_ACCEPTABLE,
        ),
        (
            "accept",
            "application/json, text/event-stream;q=NaN",
            StatusCode::NOT_ACCEPTABLE,
        ),
        (VERSION_HEADER, "1900-01-01", StatusCode::BAD_REQUEST),
        (SESSION_HEADER, "", StatusCode::BAD_REQUEST),
        (SESSION_HEADER, "contains a space", StatusCode::BAD_REQUEST),
    ] {
        let mut request = endpoint
            .request(Method::POST, Some(&session))
            .header("content-type", "application/json")
            .body(PING)
            .build()
            .unwrap();
        request.headers_mut().insert(
            reqwest::header::HeaderName::from_bytes(header.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
        assert_eq!(
            endpoint.client.execute(request).unwrap().status(),
            expected,
            "{header}: {value}"
        );
    }
    for (header, value) in [
        (VERSION_HEADER, PROTOCOL_VERSION),
        (SESSION_HEADER, session.as_str()),
        ("content-type", "application/json"),
    ] {
        let mut request = endpoint
            .request(Method::POST, Some(&session))
            .header("content-type", "application/json")
            .body(PING)
            .build()
            .unwrap();
        request.headers_mut().append(
            reqwest::header::HeaderName::from_bytes(header.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
        let expected = if header == "content-type" {
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        } else {
            StatusCode::BAD_REQUEST
        };
        assert_eq!(
            endpoint.client.execute(request).unwrap().status(),
            expected,
            "duplicate {header}"
        );
    }
    let accepted = endpoint
        .request(Method::POST, Some(&session))
        .header("content-type", "application/json; charset=utf-8")
        .header("content-encoding", "identity")
        .body(PING)
        .send()
        .unwrap();
    assert_eq!(rpc(accepted)["result"], json!({}));
    let mut missing_media = endpoint
        .request(Method::POST, Some(&session))
        .body(PING)
        .build()
        .unwrap();
    missing_media.headers_mut().remove("content-type");
    assert_eq!(
        endpoint.client.execute(missing_media).unwrap().status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let mut missing_accept = endpoint
        .request(Method::POST, Some(&session))
        .header("content-type", "application/json")
        .body(PING)
        .build()
        .unwrap();
    missing_accept.headers_mut().remove("accept");
    assert_eq!(
        endpoint.client.execute(missing_accept).unwrap().status(),
        StatusCode::NOT_ACCEPTABLE
    );
}

#[test]
fn request_size_and_json_depth_bounds_do_not_execute_the_handler() {
    let mut bounded = config();
    bounded.limits.request_bytes = 512;
    bounded.limits.json_depth = 8;
    let calls = Arc::new(AtomicUsize::new(0));
    let endpoint = TestEndpoint::new(
        bounded,
        Fixture {
            calls: calls.clone(),
            ..Fixture::default()
        },
    );
    let session = endpoint.ready();
    assert_eq!(
        endpoint.post(Some(&session), &" ".repeat(513)).status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let mut nested_value = json!(0);
    for _ in 0..10 {
        nested_value = json!([nested_value]);
    }
    let nested = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
        "name": "test_mixed", "arguments": {"nested": nested_value}
    }})
    .to_string();
    assert_eq!(
        rpc(endpoint.post(Some(&session), &nested))["error"]["code"],
        -32700
    );
    assert_eq!(
        endpoint.post(None, &nested).status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        rpc(endpoint.post(Some(&session), PING))["result"],
        json!({})
    );
}

#[test]
fn encoded_media_output_is_bounded_and_keeps_accepted_prefix_without_retry() {
    let mut bounded = config();
    bounded.limits.response_bytes = 4096;
    let calls = Arc::new(AtomicUsize::new(0));
    let endpoint = TestEndpoint::new(
        bounded,
        Fixture {
            calls: calls.clone(),
            ..Fixture::default()
        },
    );
    let session = endpoint.ready();
    let response = endpoint.post(Some(&session), &call("test_large"));
    assert_eq!(response.status(), StatusCode::OK);
    let text = response.text().unwrap();
    assert!(text.len() <= 4096);
    let response: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        response["result"]["content"][0]["text"],
        "accepted before limit"
    );
    assert_eq!(response["result"]["content"].as_array().unwrap().len(), 2);
    assert!(response["result"]["content"][1]["text"]
        .as_str()
        .unwrap()
        .contains("response budget"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        rpc(endpoint.post(Some(&session), PING))["result"],
        json!({})
    );
}

#[test]
fn an_id_that_cannot_fit_the_response_budget_closes_only_its_session() {
    let mut bounded = config();
    bounded.limits.response_bytes = 4096;
    let endpoint = TestEndpoint::new(bounded, Fixture::default());
    let first = endpoint.ready();
    let second = endpoint.ready();
    let body = json!({"jsonrpc": "2.0", "id": "x".repeat(3000), "method": "ping"}).to_string();
    assert_eq!(
        endpoint.post(Some(&first), &body).status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        endpoint.post(Some(&first), PING).status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(rpc(endpoint.post(Some(&second), PING))["result"], json!({}));
}

#[test]
fn bounded_admission_rejects_excess_work_while_a_native_call_is_running() {
    let mut bounded = config();
    bounded.max_requests = 1;
    let (fixture, control) = blocking_fixture();
    let endpoint = TestEndpoint::new(bounded, fixture);
    let session = endpoint.ready();
    let request = endpoint
        .request(Method::POST, Some(&session))
        .header("content-type", "application/json")
        .body(call("test_block"));
    let caller = thread::spawn(move || request.send().unwrap());
    control.started.recv_timeout(WAIT).unwrap();
    let rejected = endpoint.post(Some(&session), &call("test_mixed"));
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(rejected.text().unwrap().contains("not dispatched"));
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
    control.release.send(()).unwrap();
    control.completed.recv_timeout(WAIT).unwrap();
    assert_eq!(rpc(caller.join().unwrap())["result"]["isError"], false);
    assert_eq!(
        rpc(endpoint.post(Some(&session), PING))["result"],
        json!({})
    );
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn disconnect_does_not_cancel_retry_or_release_admission_for_a_running_operation() {
    let mut bounded = config();
    bounded.max_requests = 1;
    let (fixture, control) = blocking_fixture();
    let endpoint = TestEndpoint::new(bounded, fixture);
    let session = endpoint.ready();
    let mut stream = endpoint.connect_raw();
    raw_post(&mut stream, endpoint.addr, &session, &call("test_block"));
    control.started.recv_timeout(WAIT).unwrap();
    stream.shutdown(Shutdown::Both).unwrap();
    drop(stream);
    assert_eq!(
        endpoint.post(Some(&session), PING).status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    control.release.send(()).unwrap();
    control.completed.recv_timeout(WAIT).unwrap();
    // Completion acknowledgement precedes final response handoff, so allow
    // only read-only pings to observe that narrow release race. Never retry a
    // native operation whose HTTP result was lost.
    let deadline = Instant::now() + WAIT;
    loop {
        let response = endpoint.post(Some(&session), PING);
        if response.status() == StatusCode::OK {
            assert_eq!(rpc(response)["result"], json!({}));
            break;
        }
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            Instant::now() < deadline,
            "disconnected call retained admission after finishing"
        );
        thread::yield_now();
    }
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn incomplete_body_times_out_without_dispatch_and_releases_its_admission_slot() {
    let mut bounded = config();
    bounded.max_requests = 1;
    bounded.body_timeout = Duration::from_millis(150);
    let calls = Arc::new(AtomicUsize::new(0));
    let endpoint = TestEndpoint::new(
        bounded,
        Fixture {
            calls: calls.clone(),
            ..Fixture::default()
        },
    );
    let session = endpoint.ready();
    let mut stream = endpoint.connect_raw();
    write!(stream,
        "POST / HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {TOKEN}\r\nAccept: {ACCEPT}\r\nContent-Type: application/json\r\nMCP-Protocol-Version: {PROTOCOL_VERSION}\r\nMcp-Session-Id: {session}\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{{",
        endpoint.addr,
    ).unwrap();
    stream.flush().unwrap();
    let mut status = String::new();
    BufReader::new(stream).read_line(&mut status).unwrap();
    assert!(status.starts_with("HTTP/1.1 408 "), "{status}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        rpc(endpoint.post(Some(&session), PING))["result"],
        json!({})
    );
}
