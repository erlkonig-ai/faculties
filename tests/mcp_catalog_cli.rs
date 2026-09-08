//! Aggregate configuration is transport-independent; HTTP options never fall
//! through to stdio, and discovery remains independent of host storage/assets.

use std::path::Path;
use std::process::{Command, Output, Stdio};

use faculties::hear::ModelConfig;
use faculties::mcp::catalog::{Catalog, Config};
use faculties::mcp::Server;
use serde_json::{json, Value};

fn cli(directory: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_faculties"));
    command
        .args(["mcp", "--pile"])
        .arg(directory.join("not-opened.pile"))
        .stdin(Stdio::null());
    for variable in [
        "PILE",
        "TRIBLESPACE_KEY",
        "DISCORD_TOKEN",
        "LINKEDIN_TOKEN",
        "DUPLEX_SESSION",
        "HEAR_MODEL_PILE",
        "HEAR_MODEL",
        "HEAR_CONFIG_JSON",
        "HEAR_TOKENIZER_JSON",
        "FACULTIES_MCP_TOKEN_FILE",
    ] {
        command.env_remove(variable);
    }
    command
}

fn assert_argument_error(output: Output, required: &str) {
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        output.stdout.is_empty(),
        "argument errors are not MCP output"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(required), "{stderr}");
}

#[test]
fn http_listener_requires_an_explicit_token_file() {
    let directory = tempfile::tempdir().unwrap();
    assert_argument_error(
        cli(directory.path())
            .args(["--http-listen", "127.0.0.1:0"])
            .output()
            .unwrap(),
        "--http-token-file",
    );
    assert_eq!(directory.path().read_dir().unwrap().count(), 0);
}

#[test]
fn http_only_options_are_not_ignored_by_stdio() {
    let directory = tempfile::tempdir().unwrap();
    for arguments in [
        ["--http-token-file", "not-read.token"],
        ["--http-origin", "https://example.test"],
    ] {
        assert_argument_error(
            cli(directory.path()).args(arguments).output().unwrap(),
            "--http-listen",
        );
    }
    assert_eq!(directory.path().read_dir().unwrap().count(), 0);
}

#[test]
fn environment_token_file_also_requires_http() {
    let directory = tempfile::tempdir().unwrap();
    assert_argument_error(
        cli(directory.path())
            .env("FACULTIES_MCP_TOKEN_FILE", "not-read.token")
            .output()
            .unwrap(),
        "--http-listen",
    );
    assert_eq!(directory.path().read_dir().unwrap().count(), 0);
}

#[test]
fn http_accepts_repeatable_origins_and_token_file_environment() {
    let directory = tempfile::tempdir().unwrap();
    let output = cli(directory.path())
        .env(
            "FACULTIES_MCP_TOKEN_FILE",
            directory.path().join("missing.token"),
        )
        .args([
            "--http-listen",
            "127.0.0.1:0",
            "--http-origin",
            "https://first.example.test",
            "--http-origin",
            "https://second.example.test",
        ])
        .output()
        .unwrap();
    // Parsing succeeded and token-file loading failed before any bind/storage
    // operation. An accidentally falling-through stdio server would exit zero.
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    assert_eq!(directory.path().read_dir().unwrap().count(), 0);
}

#[test]
fn catalog_discovery_preserves_all_adapters_without_opening_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = Config::new(directory.path().join("office.pile"));
    config.key = Some(directory.path().join("office.key"));
    config.discord_token = Some("discovery-must-not-reveal-discord-token".into());
    config.linkedin_token = Some("discovery-must-not-reveal-linkedin-token".into());
    config.duplex_session = Some(directory.path().join("duplex-session"));
    config.hear = Some(ModelConfig {
        pile: directory.path().join("hear.pile"),
        model: "discovery-must-not-load-model".into(),
        config_json: directory.path().join("config.json"),
        tokenizer_json: directory.path().join("tokenizer.json"),
    });
    let catalog = Catalog::new(config);
    let registrations = catalog.registrations();
    let prefixes: Vec<_> = registrations
        .iter()
        .map(|faculty| faculty.tools()[0].name.split('_').next().unwrap())
        .collect();
    assert_eq!(
        prefixes,
        [
            "archive",
            "atlas",
            "body",
            "bootstrap",
            "cognition",
            "compass",
            "decide",
            "discord",
            "duplex",
            "files",
            "gauge",
            "habit",
            "headspace",
            "hear",
            "imagine",
            "linkedin",
            "mail",
            "memory",
            "message",
            "orient",
            "patience",
            "planner",
            "posture",
            "reason",
            "relations",
            "secrets",
            "status",
            "teams",
            "triage",
            "viewer",
            "voice",
            "web",
            "wiki",
        ]
    );
    let mut server = Server::new(&registrations).unwrap();
    let initialize = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "catalog-test", "version": "1"}
        }
    });
    let response = server
        .dispatch(serde_json::to_vec(&initialize).unwrap().into())
        .unwrap()
        .unwrap();
    let response: Value = serde_json::from_str(&response).unwrap();
    assert!(response.get("error").is_none(), "{response}");
    assert!(server
        .dispatch(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "method": "notifications/initialized"
            }))
            .unwrap()
            .into()
        )
        .unwrap()
        .is_none());
    let response = server
        .dispatch(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/list"
            }))
            .unwrap()
            .into(),
        )
        .unwrap()
        .unwrap();
    assert!(!response.contains("discovery-must-not-"));
    let response: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(response["result"]["tools"].as_array().unwrap().len(), 218);
    assert_eq!(directory.path().read_dir().unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
mod http_process {
    use super::*;
    use std::fs;
    use std::io::{self, Read, Write};
    use std::net::SocketAddr;
    use std::os::fd::AsRawFd;
    use std::process::{Child, ChildStderr};
    use std::thread;
    use std::time::{Duration, Instant};

    const WAIT: Duration = Duration::from_secs(5);
    const TOKEN: &str = "http-cli-test-only-not-a-real-credential-0123456789";

    struct Process(Child);

    impl Process {
        fn stop(&mut self) -> io::Result<()> {
            if self.0.try_wait()?.is_some() {
                return Ok(());
            }
            self.0.kill()?;
            let deadline = Instant::now() + WAIT;
            loop {
                if self.0.try_wait()?.is_some() {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "spawned HTTP CLI did not exit after kill",
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Drop for Process {
        fn drop(&mut self) {
            // Runs on assertion failures too, and never targets a process
            // other than this test's owned child. Reaping is deadline-bounded.
            if let Err(error) = self.stop() {
                eprintln!("HTTP CLI fixture cleanup failed: {error}");
            }
        }
    }

    fn nonblocking(pipe: &impl AsRawFd) {
        let fd = pipe.as_raw_fd();
        // SAFETY: the pipe owns this live descriptor, and fcntl only updates
        // its I/O flags. It neither closes nor transfers ownership of the fd.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert_ne!(flags, -1, "{}", io::Error::last_os_error());
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            -1,
            "{}",
            io::Error::last_os_error()
        );
    }

    fn startup(process: &mut Process, stderr: &mut ChildStderr) -> SocketAddr {
        nonblocking(stderr);
        let deadline = Instant::now() + WAIT;
        let mut received = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            match stderr.read(&mut buffer) {
                Ok(0) => panic!(
                    "HTTP CLI closed stderr before startup: {}",
                    String::from_utf8_lossy(&received)
                ),
                Ok(count) => {
                    received.extend_from_slice(&buffer[..count]);
                    assert!(received.len() <= 8192, "unexpectedly large startup output");
                    for line in received
                        .split_inclusive(|byte| *byte == b'\n')
                        .filter(|line| line.ends_with(b"\n"))
                    {
                        let line = String::from_utf8_lossy(line);
                        if let Some(address) = line
                            .strip_prefix("faculties MCP HTTP: http://")
                            .and_then(|line| line.split('/').next())
                        {
                            let address: SocketAddr = address.parse().unwrap();
                            assert!(address.ip().is_loopback());
                            assert_ne!(address.port(), 0);
                            return address;
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("read HTTP CLI startup: {error}"),
            }
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "HTTP CLI exited before startup: {}",
                String::from_utf8_lossy(&received)
            );
            assert!(
                Instant::now() < deadline,
                "HTTP CLI startup timed out: {}",
                String::from_utf8_lossy(&received)
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn http_cli_detaches_launcher_pipes_without_retaining_protocol_clones() {
        let directory = tempfile::tempdir().unwrap();
        let mut token_file = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        writeln!(token_file, "{TOKEN}").unwrap();
        token_file.flush().unwrap();
        let key = directory.path().join("not-opened.key");
        let mut process = Process(
            cli(directory.path())
                .args(["--http-listen", "127.0.0.1:0", "--http-token-file"])
                .arg(token_file.path())
                .arg("--key")
                .arg(&key)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let stdin = process.0.stdin.take().unwrap();
        let mut stdout = process.0.stdout.take().unwrap();
        let mut stderr = process.0.stderr.take().unwrap();
        let launcher_input = fs::read_link(format!("/proc/self/fd/{}", stdin.as_raw_fd())).unwrap();
        let launcher_output =
            fs::read_link(format!("/proc/self/fd/{}", stdout.as_raw_fd())).unwrap();
        let diagnostics = fs::read_link(format!("/proc/self/fd/{}", stderr.as_raw_fd())).unwrap();
        let address = startup(&mut process, &mut stderr);
        let child_fds = Path::new("/proc")
            .join(process.0.id().to_string())
            .join("fd");
        assert_eq!(
            fs::read_link(child_fds.join("0")).unwrap(),
            Path::new("/dev/null")
        );
        assert_eq!(fs::read_link(child_fds.join("1")).unwrap(), diagnostics);
        assert_eq!(fs::read_link(child_fds.join("2")).unwrap(), diagnostics);
        for entry in fs::read_dir(&child_fds).unwrap() {
            let entry = entry.unwrap();
            let target = match fs::read_link(entry.path()) {
                Ok(target) => target,
                // The HTTP runtime may close an unrelated descriptor while
                // procfs is enumerated; standard streams remain stable.
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => panic!("read child descriptor: {error}"),
            };
            assert_ne!(target, launcher_input, "retained launcher stdin: {entry:?}");
            assert_ne!(
                target, launcher_output,
                "retained launcher stdout: {entry:?}"
            );
        }
        nonblocking(&stdout);
        assert_eq!(
            stdout.read(&mut [0_u8; 1]).unwrap(),
            0,
            "launcher stdout is EOF"
        );

        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(WAIT)
            .build()
            .unwrap();
        let url = format!("http://{address}/");
        let post = |body: Value| {
            client
                .post(&url)
                .bearer_auth(TOKEN)
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", faculties::mcp::PROTOCOL_VERSION)
                .json(&body)
        };
        let initialized = post(json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": faculties::mcp::PROTOCOL_VERSION, "capabilities": {},
                "clientInfo": {"name": "cli-fd-test", "version": "1"}
            }
        }))
        .send()
        .unwrap()
        .error_for_status()
        .unwrap();
        let session = initialized.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        let initialized: Value = initialized.json().unwrap();
        assert!(initialized.get("error").is_none(), "{initialized}");
        assert_eq!(
            post(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
                .header("mcp-session-id", &session)
                .send()
                .unwrap()
                .status(),
            reqwest::StatusCode::ACCEPTED
        );
        let listed: Value = post(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
            .header("mcp-session-id", &session)
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 218);
        assert!(!directory.path().join("not-opened.pile").exists());
        assert!(!key.exists());
        assert_eq!(
            directory.path().read_dir().unwrap().count(),
            1,
            "only the synthetic token exists"
        );
        process.stop().unwrap();
    }
}
