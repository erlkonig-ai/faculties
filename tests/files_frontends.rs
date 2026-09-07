use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anybytes::Bytes;
use base64::Engine as _;
use faculties::archive_source::{canonical_json, canonical_json_string as quote};
use faculties::files::{cli, mcp, stage, Files};
use faculties::mcp::{Faculty, Server};
use faculties::out::{Out, Part};
use faculties::schemas::files::DEFAULT_SCOPE_ID;
use faculties::spec::CliRequest;
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

    fn mcp(&self) -> mcp::Files {
        mcp::Files::new(self.pile.clone(), Some(self.key.clone()))
    }

    fn files(&self) -> Files {
        Files::new(self.pile.clone(), Some(self.key.clone()))
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
fn explicit_frontends_present_the_same_selected_content() {
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
        let CliRequest::Invoke(cli) = cli::SPEC
            .lower_cli_from([
                "files",
                "--pile",
                fixture.pile.to_str().unwrap(),
                "--key",
                fixture.key.to_str().unwrap(),
                "view",
                &fixture.ids[index],
            ])
            .unwrap()
        else {
            panic!("expected invocation")
        };
        let mut cli_parts = Vec::new();
        cli::execute(
            &cli,
            &mut Out::new(&mut |part| {
                cli_parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
        let mut mcp_parts = Vec::new();
        fixture
            .mcp()
            .call(
                "files_view",
                serde_json::to_vec(&serde_json::json!({"id": fixture.ids[index]}))
                    .unwrap()
                    .into(),
                &mut Out::new(&mut |part| {
                    mcp_parts.push(part);
                    Ok(())
                }),
            )
            .unwrap();
        assert_eq!(cli_parts, [expected.clone()]);
        assert_eq!(mcp_parts, [expected]);
    }
}

#[test]
fn files_mcp_returns_real_image_audio_and_binary_export_bytes() {
    let fixture = Fixture::new();
    let files = fixture.mcp();
    let registrations: [&dyn Faculty; 1] = [&files];
    let mut server = Server::new(&registrations).unwrap();
    initialize(&mut server);
    for (index, kind, mime, bytes) in [
        (1, "image", "image/png", PNG),
        (2, "audio", "audio/wav", fixture.audio.as_slice()),
    ] {
        let response = request(&mut server, &format!(r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"files_view","arguments":{{"id":{}}}}}}}"#, quote(&fixture.ids[index]))).unwrap();
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
    for (index, bytes) in [TEXT, PNG, fixture.audio.as_slice(), BINARY]
        .into_iter()
        .enumerate()
    {
        let response = request(&mut server, &format!(r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"files_get","arguments":{{"id":{}}}}}}}"#, quote(&fixture.ids[index]))).unwrap();
        assert!(response.contains(r#""isError":false"#));
        assert!(response.contains(r#""type":"resource""#));
        assert!(response.contains(r#""mimeType":"application/octet-stream""#));
        assert!(!response.contains(r#""type":"image""#));
        assert!(!response.contains(r#""type":"audio""#));
        assert!(response.contains(&format!(
            r#""blob":"{}""#,
            base64::engine::general_purpose::STANDARD.encode(bytes)
        )));
    }
}

#[test]
fn executable_cli_keeps_export_exact_and_view_display_oriented() {
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
        .args(["view", &fixture.ids[0]])
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
        .args(["view", &fixture.ids[1]])
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
fn executable_exports_ignore_the_perception_endpoint_even_for_media_files() {
    let fixture = Fixture::new();
    for (index, bytes) in [TEXT, PNG, fixture.audio.as_slice(), BINARY]
        .into_iter()
        .enumerate()
    {
        let output = fixture
            .cli()
            .env("DRIVE_ENDPOINT", "deliberately-not-an-endpoint")
            .env("DRIVE_KEY", fixture._directory.path().join("absent.key"))
            .args(["get", &fixture.ids[index], "@-"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "raw export must not connect to a sensory endpoint: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, bytes, "export {index} changed its bytes");

        let path = fixture._directory.path().join(format!("export-{index}"));
        let disk = fixture
            .cli()
            .env("DRIVE_ENDPOINT", "deliberately-not-an-endpoint")
            .env("DRIVE_KEY", fixture._directory.path().join("absent.key"))
            .args(["get", &fixture.ids[index]])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            disk.status.success(),
            "{}",
            String::from_utf8_lossy(&disk.stderr)
        );
        assert!(disk.stdout.is_empty());
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

#[test]
fn executable_perception_endpoint_failure_does_not_fall_back_to_stdout() {
    let fixture = Fixture::new();
    let output = fixture
        .cli()
        .env("DRIVE_ENDPOINT", "deliberately-not-an-endpoint")
        .args(["view", &fixture.ids[0]])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "failed perception was rerouted");
    assert!(String::from_utf8_lossy(&output.stderr).contains("configured Drive output"));
}

#[test]
fn cli_batch_stdin_remains_usable_but_mcp_selectors_are_literal() {
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
    let mut parts = Vec::new();
    fixture
        .mcp()
        .call(
            "files_resolve",
            Bytes::from(br#"{"selectors":["@-"]}"#.to_vec()),
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
    assert!(parts
        .iter()
        .any(|part| matches!(part, Part::Text { text } if text.contains("UNRESOLVED"))));
}

#[test]
fn selected_file_emission_failure_propagates_without_retrying_output() {
    let fixture = Fixture::new();
    let mut count = 0;
    let error = fixture
        .mcp()
        .call(
            "files_view",
            serde_json::to_vec(&serde_json::json!({"id": fixture.ids[1]}))
                .unwrap()
                .into(),
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
        .args(["view", &fixture.ids[0]])
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
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{{"name":"files_view","arguments":{{"id":{}}}}}}}"#, quote(&fixture.ids[0])).unwrap();
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":6,"method":"ping"}}"#).unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let protocol = String::from_utf8(output.stdout).expect("no raw binary in JSON-RPC stdout");
    let responses = protocol.lines().collect::<Vec<_>>();
    assert_eq!(
        responses.len(),
        6,
        "file reads must not consume protocol requests"
    );
    for response in responses {
        canonical_json(Bytes::from(response.as_bytes().to_vec())).unwrap();
    }
    assert!(
        !protocol.contains("\"isError\":true"),
        "native commands must reach their configured pile"
    );
    assert_eq!(protocol.matches("\"code\":-32602").count(), 3);
    assert!(
        protocol.contains("\"isError\":false"),
        "valid view reaches native pile"
    );
    assert!(protocol.ends_with("{\"jsonrpc\":\"2.0\",\"id\":6,\"result\":{}}\n"));
}

#[test]
fn library_byte_import_and_export_need_no_frontend_or_transport() {
    let fixture = Fixture::new();
    let files = fixture.files();
    let id = files
        .add_bytes(
            BINARY.to_vec().into(),
            "native.bin",
            "application/octet-stream",
            &[],
        )
        .unwrap();
    let exported = files.get(&format!("{id:x}")).unwrap();
    assert_eq!(exported.bytes.as_ref(), BINARY);
    assert!(exported.uri().starts_with("files:"));
    let other = files
        .add_bytes(
            BINARY.to_vec().into(),
            "another-name.bin",
            "application/octet-stream",
            &[],
        )
        .unwrap();
    assert_ne!(id, other);
    assert_eq!(
        files.get(&exported.uri()).unwrap().bytes.as_ref(),
        BINARY,
        "a content URI does not need one winning filename"
    );
    let broken = Files::new(
        fixture.pile.clone(),
        Some(fixture._directory.path().join("absent.key")),
    );
    let error = broken.imports().unwrap_err();
    assert!(format!("{error:#}").contains("absent.key"), "{error:#}");
}

#[test]
fn mcp_has_independent_schemas_and_rejects_host_conventions_before_storage() {
    let missing = tempfile::tempdir().unwrap();
    let pile = missing.path().join("never-open.pile");
    let files = mcp::Files::new(pile.clone(), None);
    let mut server = Server::new(&[&files]).unwrap();
    initialize(&mut server);
    let response = request(
        &mut server,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();
    let descriptors = json["result"]["tools"].as_array().unwrap();
    let get = descriptors
        .iter()
        .find(|tool| tool["name"] == "files_get")
        .unwrap();
    assert_eq!(
        get["inputSchema"]["properties"].as_object().unwrap().len(),
        1
    );
    assert!(get["inputSchema"]["properties"].get("id").is_some());
    let add = descriptors
        .iter()
        .find(|tool| tool["name"] == "files_add")
        .unwrap();
    assert!(add["inputSchema"]["properties"].get("path").is_none());
    assert!(add["inputSchema"]["properties"].get("data").is_some());
    for (name, arguments) in [
        ("files_get", r#"{"id":"unused","output":"/dev/stdout"}"#),
        ("files_get", r#"{"id":"unused","pile":"foreign.pile"}"#),
        ("files_get", r#"{"id":"unused","id":"second"}"#),
        ("files_add", r#"{"path":"/etc/passwd"}"#),
        ("files_resolve", r#"{"input":"@/dev/stdin"}"#),
        ("files_tree", r#"{"id":"unused","depth":"10"}"#),
        ("files_view", r#"{"id":"unused","max_bytes":-1}"#),
        ("files_view", r#"{"id":"unused","max_bytes":0}"#),
        ("files_view", r#"{"id":"unused","max_dimension":0}"#),
        ("files_view", r#"{"id":"unused","accept":[]}"#),
        (
            "files_view",
            r#"{"id":"unused","accept":["image/png;q=1"]}"#,
        ),
    ] {
        let response = request(&mut server, &format!(r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":{},"arguments":{arguments}}}}}"#, quote(name))).unwrap();
        assert!(response.contains(r#""code":-32602"#), "{response}");
        assert!(!pile.exists());
    }
}

#[test]
fn mcp_add_accepts_bytes_without_a_host_path_and_get_returns_them() {
    let fixture = Fixture::new();
    let files = fixture.mcp();
    let mut parts = Vec::new();
    let args = serde_json::json!({
        "data": base64::engine::general_purpose::STANDARD.encode(TEXT),
        "name": "uploaded.txt", "mime": "text/plain", "tags": ["upload"]
    });
    files
        .call(
            "files_add",
            serde_json::to_vec(&args).unwrap().into(),
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
    let Part::Text { text } = &parts[0] else {
        panic!("file reference");
    };
    let reference = text.trim();
    let returned = fixture.files().get(reference).unwrap();
    assert_eq!(returned.bytes.as_ref(), TEXT);
}

#[test]
fn mcp_image_conversion_does_not_change_the_original_export() {
    let fixture = Fixture::new();
    let original = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
        32,
        16,
        image::Rgb([10, 20, 30]),
    ));
    let mut buffer = std::io::Cursor::new(Vec::new());
    original
        .write_to(&mut buffer, image::ImageFormat::Bmp)
        .unwrap();
    let bytes = buffer.into_inner();
    let id = fixture
        .files()
        .add_bytes(bytes.clone().into(), "original.bmp", "image/bmp", &[])
        .unwrap();
    let args =
        serde_json::json!({"id": format!("{id:x}"), "accept": ["image/png"], "max_dimension": 8});
    let mut parts = Vec::new();
    fixture
        .mcp()
        .call(
            "files_view",
            serde_json::to_vec(&args).unwrap().into(),
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
    let Part::Image {
        bytes: viewed,
        mime_type,
    } = &parts[0]
    else {
        panic!("image");
    };
    assert_eq!(mime_type, "image/png");
    let decoded = image::load_from_memory(viewed.as_ref()).unwrap();
    assert_eq!((decoded.width(), decoded.height()), (8, 4));
    assert_eq!(
        fixture
            .files()
            .get(&format!("{id:x}"))
            .unwrap()
            .bytes
            .as_ref(),
        bytes
    );
}

fn serve_once(body: &'static [u8]) -> (String, std::thread::JoinHandle<()>) {
    use std::io::{BufRead, BufReader};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/download", listener.local_addr().unwrap());
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                break;
            }
        }
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
        let _ = stream.write_all(body);
    });
    (url, worker)
}

#[test]
fn fetched_filename_never_writes_or_removes_a_host_file() {
    let fixture = Fixture::new();
    let sentinel = fixture._directory.path().join("keep-me.txt");
    fs::write(&sentinel, b"unrelated original").unwrap();
    let (url, worker) = serve_once(TEXT);
    let mut parts = Vec::new();
    fixture
        .mcp()
        .call(
            "files_fetch",
            serde_json::to_vec(&serde_json::json!({
                "url": url, "name": sentinel, "max_bytes": 1024,
            }))
            .unwrap()
            .into(),
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
    worker.join().unwrap();
    assert_eq!(fs::read(&sentinel).unwrap(), b"unrelated original");
    let Part::Text { text } = &parts[0] else {
        panic!("import report");
    };
    let reference = text.split_whitespace().next().unwrap();
    assert_eq!(fixture.files().get(reference).unwrap().bytes.as_ref(), TEXT);
    assert!(
        fixture.files().imports().unwrap().contains(&url),
        "URL provenance replaces a staging path"
    );
}

#[test]
fn download_budget_rejects_oversized_content_without_publication() {
    let fixture = Fixture::new();
    let (url, worker) = serve_once(TEXT);
    let error = fixture
        .mcp()
        .call(
            "files_fetch",
            serde_json::to_vec(&serde_json::json!({
                "url": url, "max_bytes": 4,
            }))
            .unwrap()
            .into(),
            &mut Out::new(&mut |_| panic!("rejected download emitted output")),
        )
        .unwrap_err();
    worker.join().unwrap();
    assert!(
        format!("{error:#}").contains("response too large"),
        "{error:#}"
    );
    assert_eq!(fixture.files().imports().unwrap(), "(no imports)\n");
}

#[test]
fn drive_default_does_not_send_undecoded_audio_containers() {
    let fixture = Fixture::new();
    let output = fixture
        .cli()
        .env("DRIVE_ENDPOINT", "not-an-endpoint")
        .args(["view", &fixture.ids[2]])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("audio conversion is not supported"));
}
