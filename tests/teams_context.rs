use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_TEST_PILE: AtomicU64 = AtomicU64::new(0);

struct TestPile {
    dir: PathBuf,
    path: PathBuf,
    key: PathBuf,
}

impl TestPile {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_TEST_PILE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "faculties-teams-context-cli-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.pile");
        let key = dir.join("test.key");
        fs::File::create(&path).unwrap();
        let signer = faculties::storage::initialize_signer(&path, Some(&key)).unwrap();
        let mut store = faculties::storage::open_pile_strict(&path).unwrap();
        faculties::storage::ensure_team_of_one_write_authority(&mut store, &signer).unwrap();
        store.close().unwrap();
        Self { dir, path, key }
    }
}

impl Drop for TestPile {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn run(pile: &TestPile, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_teams"))
        .env_remove("TEAMS_CLIENT_SECRET")
        .arg("--pile")
        .arg(&pile.path)
        .arg("--key")
        .arg(&pile.key)
        .arg("--tenant")
        .arg("tenant.example")
        .args(args)
        .output()
        .unwrap()
}

fn success(output: Output) -> (String, String) {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

#[test]
fn context_roundtrips_and_auth_status_stays_credential_safe() {
    let pile = TestPile::new();
    let boundary = "Work-only context; keep private conversation out of workplace communication.";
    let (set_stdout, _) = success(run(
        &pile,
        &["context", "set", "Bulti", "--boundary", boundary],
    ));
    assert!(set_stdout.contains("present_as: Bulti"));
    assert!(set_stdout.contains(boundary));

    let (show_stdout, _) = success(run(&pile, &["context", "show"]));
    assert!(show_stdout.contains("present_as: Bulti"));
    assert!(show_stdout.contains("context: professional/work-only"));
    assert!(show_stdout.contains(boundary));

    let (status_stdout, status_stderr) = success(run(&pile, &["auth", "status"]));
    assert!(status_stderr.contains("PRESENT AS Bulti"));
    assert!(status_stderr.contains(boundary));
    assert!(status_stdout.contains("tenant: tenant.example"));
    assert!(status_stdout.contains("auth_profile: (unset)"));
}

#[test]
fn outward_mutation_identity_gate_runs_before_auth_or_network() {
    let pile = TestPile::new();
    success(run(
        &pile,
        &[
            "context",
            "set",
            "Bulti",
            "--boundary",
            "Work-only boundary",
        ],
    ));

    let missing = run(&pile, &["send", "chat-id", "hello"]);
    assert!(!missing.status.success());
    let missing_stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(missing_stderr.contains("--as Bulti"));
    assert!(!missing_stderr.contains("token command"));
    assert!(!missing_stderr.contains("graph.microsoft.com"));

    let mismatch = run(&pile, &["send", "--as", "OtherPersona", "chat-id", "hello"]);
    assert!(!mismatch.status.success());
    let mismatch_stderr = String::from_utf8_lossy(&mismatch.stderr);
    assert!(mismatch_stderr.contains("presentation mismatch"));
    assert!(!mismatch_stderr.contains("token command"));
    assert!(!mismatch_stderr.contains("graph.microsoft.com"));

    for args in [
        vec!["presence", "set", "--as", "OtherPersona", "Available"],
        vec![
            "chat",
            "invite",
            "--as",
            "OtherPersona",
            "chat-id",
            "user-id",
        ],
        vec!["chat", "create", "--as", "OtherPersona", "user-id"],
    ] {
        let output = run(&pile, &args);
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("presentation mismatch"), "stderr: {stderr}");
        assert!(!stderr.contains("graph.microsoft.com"));
    }
}

#[test]
fn plaintext_oauth_sidecar_flags_are_not_cli_surface() {
    let pile = TestPile::new();
    for removed in ["--token", "--token-command", "--auth-file"] {
        let rejected = run(
            &pile,
            &[
                removed,
                "@/definitely/missing/teams-oauth",
                "auth",
                "status",
            ],
        );
        assert!(!rejected.status.success());
        let stderr = String::from_utf8_lossy(&rejected.stderr);
        assert!(stderr.contains("unexpected argument"), "stderr: {stderr}");
        assert!(!stderr.contains("read token from"));
    }
}

#[test]
fn literal_client_secret_is_rejected_without_echoing_it() {
    let pile = TestPile::new();
    let rejected = run(
        &pile,
        &[
            "login",
            "--tenant",
            "tenant.example",
            "--client-id",
            "client-id",
            "--client-secret",
            "do-not-echo-this-secret",
        ],
    );
    assert!(!rejected.status.success());
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        stderr.contains("accepts only @path or @-"),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("do-not-echo-this-secret"));
}
