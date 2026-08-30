//! The three brokered verbs, end to end, over a real pile and no network.
//!
//! `web request` writes the ask, `egress serve --once` answers it, `web
//! result` reads the answer. The broker here has no credential — this test
//! never sets one and the pile has no Headspace configuration — so it refuses
//! with `policy` before any socket could be opened. That is the point of the
//! test as much as a convenience: the refusal is *recorded*, and the read path
//! reports it as a denial with a reason rather than as a hang or a silence.

use std::fs::File;
use std::path::PathBuf;
use std::process::Command;

use faculties::storage::initialize_signer;

struct Fixture {
    _directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("cli.pile");
    let key = directory.path().join("cli.key");
    File::create(&pile).unwrap();
    initialize_signer(&pile, Some(&key)).unwrap();
    Fixture {
        _directory: directory,
        pile,
        key,
    }
}

impl Fixture {
    fn run(&self, binary: &str, arguments: &[&str]) -> String {
        let output = Command::new(binary)
            .arg("--pile")
            .arg(&self.pile)
            .arg("--key")
            .arg(&self.key)
            .args(arguments)
            // Never let an ambient credential turn this into a live call.
            .env_remove("PILE")
            .env_remove("TRIBLESPACE_KEY")
            .output()
            .expect("run faculty binary");
        assert!(
            output.status.success(),
            "{binary} {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("faculty output is utf-8")
    }
}

fn request_id(output: &str) -> String {
    output
        .lines()
        .find_map(|line| line.strip_prefix("request: "))
        .expect("request prints its id")
        .trim()
        .to_owned()
}

#[test]
fn request_serve_result_round_trips_and_records_the_refusal() {
    let fixture = fixture();

    // 1. The sandboxed side asks. No network, no credential flags at all.
    let asked = fixture.run(
        env!("CARGO_BIN_EXE_web"),
        &[
            "request",
            "https://example.test/page",
            "--kind",
            "fetch",
            "--max-characters",
            "500",
        ],
    );
    let id = request_id(&asked);
    assert!(asked.contains("status: pending"));

    // 2. Unanswered reads as pending, which is not a failure: the command
    //    succeeds and says so.
    let pending = fixture.run(env!("CARGO_BIN_EXE_web"), &["result", &id]);
    assert!(pending.contains("status: pending"), "{pending}");
    assert!(pending.contains("This is not a failure"), "{pending}");

    // 3. The broker sweeps once. It holds no credential here, so it refuses.
    let served = fixture.run(env!("CARGO_BIN_EXE_egress"), &["serve", "--once"]);
    assert!(served.contains(&format!("denied {id}")), "{served}");
    assert!(served.contains("policy:"), "{served}");

    // 4. The refusal is readable, with its category and its reason.
    let answered = fixture.run(env!("CARGO_BIN_EXE_web"), &["result", &id]);
    assert!(answered.contains("status: denied"), "{answered}");
    assert!(answered.contains("denial: policy"), "{answered}");
    assert!(answered.contains("reason: "), "{answered}");

    // 5. The audit query sees the whole crossing.
    let listed = fixture.run(env!("CARGO_BIN_EXE_egress"), &["list"]);
    assert!(listed.contains(&id), "{listed}");
    assert!(listed.contains("https://example.test/page"), "{listed}");
    assert!(listed.contains("-> denied (policy)"), "{listed}");
    assert!(listed.contains("max-characters: 500"), "{listed}");

    // 6. A denial is terminal: a second sweep does not re-serve it.
    let again = fixture.run(env!("CARGO_BIN_EXE_egress"), &["serve", "--once"]);
    assert!(!again.contains(&id), "{again}");
}

#[test]
fn an_unknown_request_id_is_an_error_while_an_unanswered_one_is_not() {
    let fixture = fixture();
    let asked = fixture.run(env!("CARGO_BIN_EXE_web"), &["request", "some query"]);
    let id = request_id(&asked);

    // A request that exists but has no answer: success, status pending.
    let pending = Command::new(env!("CARGO_BIN_EXE_web"))
        .args(["--pile", fixture.pile.to_str().unwrap()])
        .args(["--key", fixture.key.to_str().unwrap()])
        .args(["result", &id])
        .output()
        .unwrap();
    assert!(pending.status.success());

    // An id no request ever had: an error, because it is a different thing.
    let unknown = Command::new(env!("CARGO_BIN_EXE_web"))
        .args(["--pile", fixture.pile.to_str().unwrap()])
        .args(["--key", fixture.key.to_str().unwrap()])
        .args(["result", "00000000000000000000000000000001"])
        .output()
        .unwrap();
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("no Egress request"));
}
