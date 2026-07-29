use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_TEST_PILE: AtomicU64 = AtomicU64::new(0);

struct TestPile {
    dir: PathBuf,
    path: PathBuf,
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
        fs::File::create(&path).unwrap();
        Self { dir, path }
    }
}

impl Drop for TestPile {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn run(pile: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_teams"))
        .arg("--pile")
        .arg(pile)
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
        &pile.path,
        &["context", "set", "Bulti", "--boundary", boundary],
    ));
    assert!(set_stdout.contains("present_as: Bulti"));
    assert!(set_stdout.contains(boundary));

    let (show_stdout, _) = success(run(&pile.path, &["context", "show"]));
    assert!(show_stdout.contains("present_as: Bulti"));
    assert!(show_stdout.contains("context: professional/work-only"));
    assert!(show_stdout.contains(boundary));

    let (status_stdout, status_stderr) = success(run(&pile.path, &["auth", "status"]));
    assert!(status_stderr.contains("PRESENT AS Bulti"));
    assert!(status_stderr.contains(boundary));
    assert!(status_stdout.contains("tenant: (unset)"));
    assert!(status_stdout.contains("app_client_secret: not configured"));
}

#[test]
fn outward_mutation_identity_gate_runs_before_auth_or_network() {
    let pile = TestPile::new();
    success(run(
        &pile.path,
        &[
            "context",
            "set",
            "Bulti",
            "--boundary",
            "Work-only boundary",
        ],
    ));

    let missing = run(&pile.path, &["send", "chat-id", "hello"]);
    assert!(!missing.status.success());
    let missing_stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(missing_stderr.contains("--as Bulti"));
    assert!(!missing_stderr.contains("token command"));
    assert!(!missing_stderr.contains("graph.microsoft.com"));

    let mismatch = run(&pile.path, &["send", "--as", "Liora", "chat-id", "hello"]);
    assert!(!mismatch.status.success());
    let mismatch_stderr = String::from_utf8_lossy(&mismatch.stderr);
    assert!(mismatch_stderr.contains("presentation mismatch"));
    assert!(!mismatch_stderr.contains("token command"));
    assert!(!mismatch_stderr.contains("graph.microsoft.com"));

    for args in [
        vec!["presence", "set", "--as", "Liora", "Available"],
        vec!["chat", "invite", "--as", "Liora", "chat-id", "user-id"],
        vec!["chat", "create", "--as", "Liora", "user-id"],
    ] {
        let output = run(&pile.path, &args);
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("presentation mismatch"), "stderr: {stderr}");
        assert!(!stderr.contains("graph.microsoft.com"));
    }
}

#[test]
fn irrelevant_token_files_are_not_resolved_before_the_identity_gate() {
    let pile = TestPile::new();
    success(run(
        &pile.path,
        &[
            "context",
            "set",
            "Bulti",
            "--boundary",
            "Work-only boundary",
        ],
    ));

    let missing_token = "@/definitely/missing/teams-token";
    let (show_stdout, _) = success(run(
        &pile.path,
        &["--token", missing_token, "context", "show"],
    ));
    assert!(show_stdout.contains("present_as: Bulti"));

    let rejected = run(
        &pile.path,
        &[
            "--token",
            missing_token,
            "send",
            "--as",
            "Liora",
            "chat-id",
            "hello",
        ],
    );
    assert!(!rejected.status.success());
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(stderr.contains("presentation mismatch"));
    assert!(!stderr.contains("read token from"));
}
