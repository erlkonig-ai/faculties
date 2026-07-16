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
            "faculties-compass-note-{}-{nonce}-{sequence}",
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

fn run(binary: &str, pile: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .arg("--pile")
        .arg(pile)
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: Output) -> String {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn id_after(line_prefix: &str, output: &str) -> String {
    output
        .lines()
        .find_map(|line| line.strip_prefix(line_prefix))
        .and_then(|tail| tail.split_whitespace().next())
        .unwrap()
        .to_owned()
}

#[test]
fn note_metadata_is_stored_and_rendered_without_hiding_history() {
    let pile = TestPile::new();
    let relations = env!("CARGO_BIN_EXE_relations");
    let compass = env!("CARGO_BIN_EXE_compass");

    let person = stdout(run(
        relations,
        &pile.path,
        &["add", "ledger-author", "--affinity", "zooid"],
    ));
    let person_id = id_after("Added ", &person);

    let added = stdout(run(
        compass,
        &pile.path,
        &[
            "--persona",
            "ledger-author",
            "add",
            "Ledger goal",
            "--note",
            "seed [source](wiki:ABCD1234)",
        ],
    ));
    let goal_id = id_after("Added goal ", &added);
    let first_note = id_after("Added note ", &added);
    assert_eq!(goal_id.len(), 32);
    assert_eq!(first_note.len(), 32);

    let added_note = stdout(run(
        compass,
        &pile.path,
        &[
            "--persona",
            "ledger-author",
            "note",
            &goal_id,
            "follow-up [code](git:DEADBEEF)",
            "--tag",
            "liora-gpt",
            "--ref",
            " exact ref ",
            "--supersedes",
            &first_note,
        ],
    ));
    let second_note = id_after("Added note ", &added_note);

    let shown = stdout(run(compass, &pile.path, &["show", &goal_id]));
    assert!(shown.contains(&format!("[{first_note}]")));
    assert!(shown.contains(&format!("[{second_note}]")));
    assert!(shown.contains(&format!("by {person_id}")));
    assert!(shown.contains("tags: #liora-gpt"));
    assert!(shown.contains("refs:  exact ref , git:DEADBEEF"));
    assert!(shown.contains(&format!("supersedes: {first_note}")));
    assert!(shown.contains("refs: wiki:ABCD1234"));
    assert!(shown.contains("⇢ git:DEADBEEF"));
    assert!(shown.contains("⇢ wiki:ABCD1234"));
}

#[test]
fn empty_refs_and_supersedes_prefixes_are_rejected() {
    let pile = TestPile::new();
    let compass = env!("CARGO_BIN_EXE_compass");
    let added = stdout(run(compass, &pile.path, &["add", "Ledger goal", "--note", "seed"]));
    let goal_id = id_after("Added goal ", &added);
    let first_note = id_after("Added note ", &added);

    let empty_ref = run(
        compass,
        &pile.path,
        &["note", &goal_id, "bad ref", "--ref", "   "],
    );
    assert!(!empty_ref.status.success());
    assert!(String::from_utf8_lossy(&empty_ref.stderr).contains("reference must not be empty"));

    let short_id = &first_note[..8];
    let prefix = run(
        compass,
        &pile.path,
        &["note", &goal_id, "bad edge", "--supersedes", short_id],
    );
    assert!(!prefix.status.success());
    assert!(String::from_utf8_lossy(&prefix.stderr).contains("full 32-char note id"));
}

#[test]
fn orient_wakes_once_for_visible_notes_and_keeps_own_notes_quiet() {
    let pile = TestPile::new();
    let relations = env!("CARGO_BIN_EXE_relations");
    let compass = env!("CARGO_BIN_EXE_compass");
    let orient = env!("CARGO_BIN_EXE_orient");

    stdout(run(relations, &pile.path, &["add", "me", "--affinity", "zooid"]));
    stdout(run(relations, &pile.path, &["add", "peer", "--affinity", "zooid"]));
    let added = stdout(run(
        compass,
        &pile.path,
        &["--persona", "me", "add", "Shared goal"],
    ));
    let goal_id = id_after("Added goal ", &added);

    let baseline = stdout(run(orient, &pile.path, &["--persona", "me", "poll"]));
    assert!(baseline.is_empty());

    let foreign = stdout(run(
        compass,
        &pile.path,
        &[
            "--persona",
            "peer",
            "note",
            &goal_id,
            "foreign observation",
        ],
    ));
    let foreign_id = id_after("Added note ", &foreign);
    let news = stdout(run(orient, &pile.path, &["--persona", "me", "poll"]));
    assert!(news.contains(&format!(
        "new note [{foreign_id}] on goal [{goal_id}]"
    )));
    assert!(stdout(run(orient, &pile.path, &["--persona", "me", "poll"])).is_empty());

    stdout(run(
        compass,
        &pile.path,
        &["--persona", "me", "note", &goal_id, "my own note"],
    ));
    assert!(stdout(run(orient, &pile.path, &["--persona", "me", "poll"])).is_empty());

    let unattributed = stdout(run(
        compass,
        &pile.path,
        &["note", &goal_id, "unattributed observation"],
    ));
    let unattributed_id = id_after("Added note ", &unattributed);
    let news = stdout(run(orient, &pile.path, &["--persona", "me", "poll"]));
    assert!(news.contains(&format!(
        "new note [{unattributed_id}] on goal [{goal_id}]"
    )));

    let unrelated = stdout(run(
        compass,
        &pile.path,
        &["--persona", "peer", "add", "Unrelated goal"],
    ));
    let unrelated_goal = id_after("Added goal ", &unrelated);
    assert!(stdout(run(orient, &pile.path, &["--persona", "me", "poll"])).is_empty());
    let direct = stdout(run(
        compass,
        &pile.path,
        &[
            "--persona",
            "peer",
            "note",
            &unrelated_goal,
            "direct ping",
            "--tag",
            "me",
        ],
    ));
    let direct_id = id_after("Added note ", &direct);
    let news = stdout(run(orient, &pile.path, &["--persona", "me", "poll"]));
    assert!(news.contains(&format!(
        "new note [{direct_id}] on goal [{unrelated_goal}]"
    )));

    let participated = stdout(run(
        compass,
        &pile.path,
        &["--persona", "peer", "add", "Participated goal"],
    ));
    let participated_goal = id_after("Added goal ", &participated);
    assert!(stdout(run(orient, &pile.path, &["--persona", "me", "poll"])).is_empty());
    stdout(run(
        compass,
        &pile.path,
        &[
            "--persona",
            "me",
            "note",
            &participated_goal,
            "joining the discussion",
        ],
    ));
    assert!(stdout(run(orient, &pile.path, &["--persona", "me", "poll"])).is_empty());
    let response = stdout(run(
        compass,
        &pile.path,
        &[
            "--persona",
            "peer",
            "note",
            &participated_goal,
            "peer response",
        ],
    ));
    let response_id = id_after("Added note ", &response);
    let news = stdout(run(orient, &pile.path, &["--persona", "me", "poll"]));
    assert!(news.contains(&format!(
        "new note [{response_id}] on goal [{participated_goal}]"
    )));
}
