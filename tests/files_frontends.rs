use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anybytes::Bytes;
use base64::Engine as _;
use faculties::archive_source::{canonical_json, canonical_json_string as quote};
use faculties::files::{command, stage};
use faculties::mcp::{Registration, Server};
use faculties::out::{Out, Part};
use faculties::schemas::files::DEFAULT_SCOPE_ID;
use faculties::spec::{Arguments, CliRequest};
use faculties::storage::{initialize_signer, publish_fragment};
use triblespace::prelude::Fragment;

// Existing real PNG from the public repository, not bytes merely labelled PNG.
const PNG: &[u8] = include_bytes!("../preview.png");
const TEXT: &[u8] = "Grüße from a file.\nNo added newline.".as_bytes();
const BINARY: &[u8] = &[0, 255, 10, 128];

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
    bytes.extend_from_slice(&16_u16.to_le_bytes()); // sample bits
    bytes.extend_from_slice(b"data");
    bytes.extend_from_slice(&2_u32.to_le_bytes());
    bytes.extend_from_slice(&0_i16.to_le_bytes());
    bytes
}

struct Fixture {
    _directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
    ids: Vec<String>,
    audio: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("files.pile");
        let key = directory.path().join("explicit.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        let audio = wav();
        let mut all = Fragment::empty();
        let mut ids = Vec::new();
        for (bytes, name, mime) in [
            (TEXT, "notes.txt", "text/plain;charset=utf-8"),
            (PNG, "preview.png", "image/png"),
            (audio.as_slice(), "silence.wav", "audio/wav"),
            (BINARY, "opaque.bin", "application/octet-stream"),
        ] {
            let fragment = stage(bytes.to_vec(), name, mime).unwrap();
            ids.push(format!("{:x}", fragment.root().unwrap()));
            all += fragment;
        }
        publish_fragment(&pile, Some(&key), DEFAULT_SCOPE_ID, all).unwrap();
        Self {
            _directory: directory,
            pile,
            key,
            ids,
            audio,
        }
    }

    fn ambient(&self) -> Arguments {
        Arguments::new()
            .with("pile", self.pile.to_string_lossy())
            .with("key", self.key.to_string_lossy())
    }

    fn cli(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_files"));
        command
            .args(["--pile"])
            .arg(&self.pile)
            .args(["--key"])
            .arg(&self.key);
        command.env_remove("DRIVE_ENDPOINT");
        command.env_remove("TRIBLESPACE_COLLECTION_FILES");
        command.env_remove("TRIBLESPACE_PEERS");
        command
    }
}

fn request(server: &mut Server<'_>, input: &str) -> Option<String> {
    let output = server
        .dispatch(Bytes::from(input.as_bytes().to_vec()))
        .unwrap();
    if let Some(output) = &output {
        canonical_json(Bytes::from(output.as_bytes().to_vec())).unwrap();
    }
    output
}

fn initialize(server: &mut Server<'_>) {
    request(server, r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"files-test","version":"1"}}}"#).unwrap();
    assert!(request(
        server,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
    )
    .is_none());
}

#[test]
fn native_files_read_uses_stored_mime_and_the_same_cli_and_mcp_handler() {
    let fixture = Fixture::new();
    for (index, expected) in [
        Part::Text {
            text: String::from_utf8(TEXT.to_vec()).unwrap(),
        },
        Part::Image {
            bytes: PNG.to_vec().into(),
            mime_type: "image/png".into(),
        },
        Part::Audio {
            bytes: fixture.audio.clone().into(),
            mime_type: "audio/wav".into(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let CliRequest::Invoke(cli) = command::SPEC
            .lower_cli_from([
                "files",
                "--pile",
                fixture.pile.to_str().unwrap(),
                "--key",
                fixture.key.to_str().unwrap(),
                "read",
                &fixture.ids[index],
            ])
            .unwrap()
        else {
            panic!("expected invocation")
        };
        let mcp = command::SPEC
            .lower_mcp(
                "files_read",
                Arguments::new().with("id", &fixture.ids[index]),
                fixture.ambient(),
            )
            .unwrap();
        for invocation in [cli, mcp] {
            let mut parts = Vec::new();
            command::execute(
                &invocation,
                &mut Out::new(&mut |part| {
                    parts.push(part);
                    Ok(())
                }),
            )
            .unwrap();
            assert!(
                parts == [expected.clone()],
                "frontend changed media part {index}"
            );
        }
    }
}

#[test]
fn files_mcp_returns_real_image_audio_and_binary_export_bytes() {
    let fixture = Fixture::new();
    let registrations = [Registration {
        spec: &command::SPEC,
        invoke: command::execute,
        ambient: fixture.ambient(),
    }];
    let mut server = Server::new(&registrations).unwrap();
    initialize(&mut server);
    for (index, kind, mime, bytes) in [
        (1, "image", "image/png", PNG),
        (2, "audio", "audio/wav", fixture.audio.as_slice()),
    ] {
        let response = request(&mut server, &format!(r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"files_read","arguments":{{"id":{}}}}}}}"#, quote(&fixture.ids[index]))).unwrap();
        assert!(response.contains(r#""isError":false"#));
        assert!(response.contains(&format!(r#""type":"{kind}""#)));
        assert!(response.contains(&format!(r#""mimeType":"{mime}""#)));
        assert!(
            response.contains(&format!(
                r#""data":"{}""#,
                base64::engine::general_purpose::STANDARD.encode(bytes)
            )),
            "exact native media bytes survive the transport"
        );
    }
    let response = request(&mut server, &format!(r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"files_get","arguments":{{"id":{},"output":"@-"}}}}}}"#, quote(&fixture.ids[3]))).unwrap();
    assert!(response.contains(r#""isError":false"#));
    assert!(response.contains(r#""type":"resource""#));
    assert!(response.contains(r#""mimeType":"application/octet-stream""#));
    assert!(response.contains(&format!(
        r#""blob":"{}""#,
        base64::engine::general_purpose::STANDARD.encode(BINARY)
    )));
}

#[test]
fn executable_cli_keeps_export_exact_and_read_display_oriented() {
    let fixture = Fixture::new();
    let exported = fixture
        .cli()
        .args(["get", &fixture.ids[3], "@-"])
        .output()
        .unwrap();
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert_eq!(exported.stdout, BINARY);
    let text = fixture
        .cli()
        .args(["read", &fixture.ids[0]])
        .output()
        .unwrap();
    assert!(
        text.status.success(),
        "{}",
        String::from_utf8_lossy(&text.stderr)
    );
    assert_eq!(text.stdout, TEXT);
    let image = fixture
        .cli()
        .args(["read", &fixture.ids[1]])
        .output()
        .unwrap();
    assert!(
        image.status.success(),
        "{}",
        String::from_utf8_lossy(&image.stderr)
    );
    assert_eq!(
        String::from_utf8(image.stdout).unwrap(),
        format!("[image: image/png, {} bytes]\n", PNG.len())
    );
}

#[test]
fn cli_batch_stdin_remains_usable_and_native_calls_cannot_consume_protocol_stdin() {
    let fixture = Fixture::new();
    let mut child = fixture
        .cli()
        .args(["resolve", "@-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{}", fixture.ids[0]).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{}\tfiles:{}\n", fixture.ids[0], fixture.ids[0])
    );
    let invocation = command::SPEC
        .lower_mcp(
            "files_resolve",
            Arguments::new().with("input", "@-"),
            fixture.ambient(),
        )
        .unwrap();
    let error = command::execute(&invocation, &mut Out::new(&mut |_| Ok(()))).unwrap_err();
    assert!(format!("{error:#}").contains("stdin"));
}

#[test]
fn selected_file_emission_failure_propagates_without_retrying_output() {
    let fixture = Fixture::new();
    let invocation = command::SPEC
        .lower_mcp(
            "files_read",
            Arguments::new().with("id", &fixture.ids[1]),
            fixture.ambient(),
        )
        .unwrap();
    let mut count = 0;
    let error = command::execute(
        &invocation,
        &mut Out::new(&mut |_| {
            count += 1;
            anyhow::bail!("consumer stopped")
        }),
    )
    .unwrap_err();
    assert_eq!(count, 1);
    assert!(format!("{error:#}").contains("consumer stopped"));
}

#[cfg(unix)]
#[test]
fn executable_mcp_preserves_native_paths_and_isolates_standard_stream_aliases() {
    use std::os::unix::ffi::OsStringExt;

    let mut fixture = Fixture::new();
    let native_directory = fixture
        ._directory
        .path()
        .join(std::ffi::OsString::from_vec(b"native-\xff".to_vec()));
    fs::create_dir(&native_directory).unwrap();
    let pile = native_directory.join("files.pile");
    let key = native_directory.join("explicit.key");
    fs::rename(&fixture.pile, &pile).unwrap();
    fs::rename(&fixture.key, &key).unwrap();
    fixture.pile = pile;
    fixture.key = key;
    let cli = fixture
        .cli()
        .args(["read", &fixture.ids[0]])
        .output()
        .unwrap();
    assert!(cli.status.success());
    assert_eq!(cli.stdout, TEXT);
    let alias = fixture._directory.path().join("stdout-alias");
    std::os::unix::fs::symlink("/dev/stdout", &alias).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_faculties"))
        .arg("mcp")
        .arg("--pile")
        .arg(&fixture.pile)
        .arg("--key")
        .arg(&fixture.key)
        .env_remove("TRIBLESPACE_COLLECTION_FILES")
        .env_remove("TRIBLESPACE_PEERS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-06-18","capabilities":{{}},"clientInfo":{{"name":"files-test","version":"1"}}}}}}"#).unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#
    )
    .unwrap();
    for (number, path) in [(2, "/dev/stdout"), (3, alias.to_str().unwrap())] {
        writeln!(stdin, r#"{{"jsonrpc":"2.0","id":{number},"method":"tools/call","params":{{"name":"files_get","arguments":{{"id":{},"output":{}}}}}}}"#, quote(&fixture.ids[3]), quote(path)).unwrap();
    }
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"files_resolve","arguments":{{"input":"@/dev/stdin"}}}}}}"#).unwrap();
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":5,"method":"ping"}}"#).unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let protocol = String::from_utf8(output.stdout).expect("no raw binary in JSON-RPC stdout");
    let responses = protocol.lines().collect::<Vec<_>>();
    assert_eq!(
        responses.len(),
        5,
        "file reads must not consume protocol requests"
    );
    for response in responses {
        canonical_json(Bytes::from(response.as_bytes().to_vec())).unwrap();
    }
    assert!(
        !protocol.contains("\"isError\":true"),
        "native commands must reach their configured pile"
    );
    assert!(protocol.ends_with("{\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{}}\n"));
}
