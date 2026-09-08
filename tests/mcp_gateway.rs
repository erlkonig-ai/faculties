//! Opt-in test of two real native workers behind the independently built
//! Playground gateway. All data, identities and tokens are disposable fixtures.
//! Run in a clean environment with PLAYGROUND_HTTP_BINARY=/absolute/path/playground:
//! cargo test --locked --no-default-features --test mcp_gateway -- --ignored

use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use faculties::files::stage;
use faculties::schemas::files::DEFAULT_SCOPE_ID;
use faculties::storage::{initialize_signer, publish_fragment};
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use triblespace::prelude::Fragment;

const PNG: &[u8] = include_bytes!("../preview.png");
const BINARY: &[u8] = &[0, 255, 10, 128];
const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"combined-test","version":"1"}}}"#;
const INITIALIZED: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const PING: &str = r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#;
// Larger than u64; neither transport may round this through a floating point ID.
const RPC_ID: &str = "1844674407370955161618446744073709551616";
const ALICE: &str = "public-alice-test-token";
const BOB: &str = "public-bob-test-token";
const RENEWED_ALICE: &str = "renewed-public-alice-test-token";

struct Process {
    child: Child,
}

impl Process {
    fn start(mut command: Command, root: &Path, address: SocketAddr) -> Self {
        let mut process = Self {
            child: command
                .env_clear()
                .env("HOME", root)
                .env("PATH", "/no-sandbox-commands")
                .env("FACULTIES_MODEL_DIR", root.join("absent-models"))
                // Native MCP must own output, not contact an ambient Drive.
                .env("DRIVE_ENDPOINT", "http://127.0.0.1:1")
                .current_dir(root)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        while TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err() {
            assert!(
                process.child.try_wait().unwrap().is_none(),
                "owned process exited before binding {address}"
            );
            assert!(Instant::now() < deadline, "process did not bind {address}");
            std::thread::sleep(Duration::from_millis(10));
        }
        process
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // Kill/reap only the exact child this test spawned, including on panic.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Tenant {
    root: PathBuf,
    pile: PathBuf,
    key: PathBuf,
    token_file: PathBuf,
    token: String,
    address: SocketAddr,
    text: String,
    audio: Vec<u8>,
    ids: Vec<String>,
}

impl Tenant {
    fn new(root: &Path, name: &str) -> Self {
        let root = root.join(name);
        fs::create_dir(&root).unwrap();
        let pile = root.join("files.pile");
        let key = root.join("signer.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        let text = format!("Grüße from {name}.\nNo added newline.");
        let audio = wav();
        let mut all = Fragment::empty();
        let mut ids = Vec::new();
        for (bytes, filename, mime) in [
            (text.as_bytes(), "notes.txt", "text/plain;charset=utf-8"),
            (PNG, "preview.png", "image/png"),
            (audio.as_slice(), "silence.wav", "audio/wav"),
            (BINARY, "opaque.bin", "application/octet-stream"),
        ] {
            // Stage real bytes without asking an image importer to load CLIP.
            let fragment = stage(bytes.to_vec(), filename, mime).unwrap();
            ids.push(format!("{:x}", fragment.root().unwrap()));
            all += fragment;
        }
        publish_fragment(&pile, Some(&key), DEFAULT_SCOPE_ID, all).unwrap();
        let token = format!("internal-{name}-fixture-token-at-least-32-characters");
        let token_file = root.join("worker.token");
        fs::write(&token_file, &token).unwrap();
        Self {
            root,
            pile,
            key,
            token_file,
            token,
            address: unused_address(),
            text,
            audio,
            ids,
        }
    }

    fn start(&self) -> Process {
        let mut command = Command::new(env!("CARGO_BIN_EXE_faculties"));
        command
            .args(["mcp", "--http-listen", &self.address.to_string()])
            .arg("--http-token-file")
            .arg(&self.token_file)
            .arg("--pile")
            .arg(&self.pile)
            .arg("--key")
            .arg(&self.key);
        Process::start(command, &self.root, self.address)
    }
}

fn unused_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn wav() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"RIFF");
    bytes.extend_from_slice(&38_u32.to_le_bytes());
    bytes.extend_from_slice(b"WAVEfmt ");
    bytes.extend_from_slice(&16_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u16.to_le_bytes()); // PCM
    bytes.extend_from_slice(&1_u16.to_le_bytes()); // mono
    bytes.extend_from_slice(&8000_u32.to_le_bytes());
    bytes.extend_from_slice(&16000_u32.to_le_bytes());
    bytes.extend_from_slice(&2_u16.to_le_bytes()); // block alignment
    bytes.extend_from_slice(&16_u16.to_le_bytes());
    bytes.extend_from_slice(b"data");
    bytes.extend_from_slice(&2_u32.to_le_bytes());
    bytes.extend_from_slice(&0_i16.to_le_bytes());
    bytes
}

fn request(
    client: &Client,
    address: SocketAddr,
    token: &str,
    session: Option<&str>,
    method: Method,
) -> RequestBuilder {
    let mut request = client
        .request(method, format!("http://{address}/"))
        .bearer_auth(token)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2025-06-18");
    if let Some(session) = session {
        request = request.header("mcp-session-id", session);
    }
    request
}

fn initialize(client: &Client, address: SocketAddr, token: &str) -> String {
    let response = request(client, address, token, None, Method::POST)
        .body(INITIALIZE)
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let session = response.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let value: Value = response.json().unwrap();
    assert_eq!(value["result"]["protocolVersion"], "2025-06-18");
    let response = request(client, address, token, Some(&session), Method::POST)
        .body(INITIALIZED)
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(response.bytes().unwrap().is_empty());
    session
}

fn call(name: &str, arguments: Value) -> String {
    let params = json!({"name": name, "arguments": arguments});
    format!(r#"{{"jsonrpc":"2.0","id":{RPC_ID},"method":"tools/call","params":{params}}}"#)
}

fn tool_body(response: Response) -> String {
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().unwrap();
    assert!(
        body.contains(&format!(r#""id":{RPC_ID}"#)),
        "RPC ID was changed"
    );
    body
}

fn successful(body: &str) -> Value {
    let value: Value = serde_json::from_str(body).unwrap();
    assert_eq!(value["result"]["isError"], false, "{body}");
    value
}

fn write_tokens(root: &Path, alice_token: &str) {
    let path = root.join("tokens.json");
    let next = root.join("next-tokens.json");
    fs::write(
        &next,
        serde_json::to_vec(&json!({"tokens": {
            (alice_token): {"tenant":"alice","backend":"jail"},
            (BOB): {"tenant":"bob","backend":"jail"}
        }}))
        .unwrap(),
    )
    .unwrap();
    if let Ok(previous) = fs::metadata(&path) {
        // Deterministic mtime change, even on a coarse-timestamp filesystem.
        let time = previous.modified().unwrap() + Duration::from_secs(2);
        fs::OpenOptions::new()
            .write(true)
            .open(&next)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(time))
            .unwrap();
    }
    fs::rename(next, path).unwrap();
}

fn gateway(binary: &Path, root: &Path, address: SocketAddr) -> Process {
    let mut command = Command::new(binary);
    command
        .args([
            "mcp-http",
            "--backend",
            "jail",
            "--bind",
            &address.to_string(),
        ])
        .arg("--tokens")
        .arg(root.join("tokens.json"))
        .arg("--faculties-workers")
        .arg(root.join("workers.json"));
    Process::start(command, root, address)
}

#[test]
#[ignore = "requires an independently-built Playground native-worker gateway"]
fn real_workers_preserve_media_isolation_revocation_and_reconnects() {
    let binary = PathBuf::from(
        std::env::var_os("PLAYGROUND_HTTP_BINARY")
            .expect("set PLAYGROUND_HTTP_BINARY to the exact cohort executable"),
    );
    assert!(binary.is_absolute());
    for variable in ["TRIBLESPACE_COLLECTION_FILES", "TRIBLESPACE_PEERS"] {
        assert!(
            std::env::var_os(variable).is_none(),
            "unset {variable} for fixture seeding"
        );
    }
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let alice = Tenant::new(root, "alice");
    let bob = Tenant::new(root, "bob");
    assert_ne!(alice.ids[0], bob.ids[0]);
    let mut alice_worker = alice.start();
    let _bob_worker = bob.start();
    write_tokens(root, ALICE);
    fs::write(
        root.join("workers.json"),
        serde_json::to_vec(&json!({"workers": [
            {"tenant":"alice","address":alice.address.to_string(),"token_file":alice.token_file},
            {"tenant":"bob","address":bob.address.to_string(),"token_file":bob.token_file}
        ]}))
        .unwrap(),
    )
    .unwrap();
    let address = unused_address();
    let mut edge = gateway(&binary, root, address);
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    let alice_session = initialize(&client, address, ALICE);
    let bob_session = initialize(&client, address, BOB);
    let direct_session = initialize(&client, alice.address, &alice.token);

    for (index, kind, mime, bytes) in [
        (0, "text", "", alice.text.as_bytes()),
        (1, "image", "image/png", PNG),
        (2, "audio", "audio/wav", alice.audio.as_slice()),
        (3, "resource", "application/octet-stream", BINARY),
    ] {
        let body = call(
            if kind == "resource" {
                "files_get"
            } else {
                "files_view"
            },
            json!({"id": alice.ids[index]}),
        );
        let routed = tool_body(
            request(&client, address, ALICE, Some(&alice_session), Method::POST)
                .body(body.clone())
                .send()
                .unwrap(),
        );
        let direct = tool_body(
            request(
                &client,
                alice.address,
                &alice.token,
                Some(&direct_session),
                Method::POST,
            )
            .body(body)
            .send()
            .unwrap(),
        );
        assert_eq!(
            routed, direct,
            "gateway must preserve the entire native frame"
        );
        let value = successful(&routed);
        let part = &value["result"]["content"][0];
        assert_eq!(part["type"], kind);
        if kind == "text" {
            assert_eq!(part["text"], alice.text);
        } else {
            let (part, field) = if kind == "resource" {
                (&part["resource"], "blob")
            } else {
                (part, "data")
            };
            assert_eq!(part["mimeType"], mime);
            assert_eq!(
                part[field],
                base64::engine::general_purpose::STANDARD.encode(bytes)
            );
        }
    }

    let alice_only = call("files_view", json!({"id": alice.ids[0]}));
    assert_eq!(
        request(&client, address, BOB, Some(&alice_session), Method::POST)
            .body(alice_only.clone())
            .send()
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let denied = tool_body(
        request(&client, address, BOB, Some(&bob_session), Method::POST)
            .header("x-tenant", "alice")
            .body(alice_only)
            .send()
            .unwrap(),
    );
    let denied: Value = serde_json::from_str(&denied).unwrap();
    assert_eq!(denied["result"]["isError"], true);
    assert!(denied["result"]["content"]
        .as_array()
        .unwrap()
        .iter()
        .all(|part| !part["text"].as_str().unwrap_or("").contains(&alice.text)));
    let bob_view = tool_body(
        request(&client, address, BOB, Some(&bob_session), Method::POST)
            .body(call("files_view", json!({"id":bob.ids[0]})))
            .send()
            .unwrap(),
    );
    assert_eq!(
        successful(&bob_view)["result"]["content"][0]["text"],
        bob.text
    );
    for (target, token) in [(alice.address, ALICE), (address, alice.token.as_str())] {
        assert_eq!(
            request(&client, target, token, None, Method::POST)
                .body(INITIALIZE)
                .send()
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    let added = tool_body(
        request(&client, address, ALICE, Some(&alice_session), Method::POST)
            .body(call(
                "files_add",
                json!({"name":"written-through-gateway.txt", "mime":"text/plain",
            "data":base64::engine::general_purpose::STANDARD.encode("gateway write")}),
            ))
            .send()
            .unwrap(),
    );
    successful(&added);
    let list = call("files_list", json!({}));
    for (token, session, visible) in [(ALICE, &alice_session, true), (BOB, &bob_session, false)] {
        let body = tool_body(
            request(&client, address, token, Some(session), Method::POST)
                .body(list.clone())
                .send()
                .unwrap(),
        );
        successful(&body);
        assert_eq!(body.contains("written-through-gateway.txt"), visible);
    }

    write_tokens(root, RENEWED_ALICE);
    assert_eq!(
        request(&client, address, ALICE, Some(&alice_session), Method::POST)
            .body(PING)
            .send()
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            &client,
            address,
            ALICE,
            Some(&alice_session),
            Method::DELETE
        )
        .send()
        .unwrap()
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            &client,
            address,
            RENEWED_ALICE,
            Some(&alice_session),
            Method::DELETE
        )
        .send()
        .unwrap()
        .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(
            &client,
            address,
            RENEWED_ALICE,
            Some(&alice_session),
            Method::POST
        )
        .body(PING)
        .send()
        .unwrap()
        .status(),
        StatusCode::NOT_FOUND
    );
    let renewed_session = initialize(&client, address, RENEWED_ALICE);

    drop(alice_worker);
    alice_worker = alice.start();
    // A stale session must not be silently recreated to replay this mutation.
    assert_eq!(
        request(
            &client,
            address,
            RENEWED_ALICE,
            Some(&renewed_session),
            Method::POST
        )
        .body(call(
            "files_add",
            json!({"name":"must-not-replay.txt", "mime":"text/plain", "data":"eA=="})
        ))
        .send()
        .unwrap()
        .status(),
        StatusCode::NOT_FOUND
    );
    let after_worker_restart = initialize(&client, address, RENEWED_ALICE);
    drop(edge);
    edge = gateway(&binary, root, address);
    assert_eq!(
        request(
            &client,
            address,
            RENEWED_ALICE,
            Some(&after_worker_restart),
            Method::POST
        )
        .body(PING)
        .send()
        .unwrap()
        .status(),
        StatusCode::NOT_FOUND
    );
    let after_gateway_restart = initialize(&client, address, RENEWED_ALICE);
    let persisted = tool_body(
        request(
            &client,
            address,
            RENEWED_ALICE,
            Some(&after_gateway_restart),
            Method::POST,
        )
        .body(list)
        .send()
        .unwrap(),
    );
    successful(&persisted);
    assert!(persisted.contains("written-through-gateway.txt"));
    assert!(!persisted.contains("must-not-replay.txt"));
    for path in [root, &alice.root, &bob.root] {
        assert!(!path.join("absent-models").exists());
    }
    drop(edge);
    drop(alice_worker);
}
