use super::*;
use crate::posture::cli::Cli;
use clap::CommandFactory;

use std::fs::File;

#[test]
fn unsupported_host_document_stops_after_its_type_header() {
    struct HeaderOnly(bool);
    impl std::io::Read for HeaderOnly {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            assert!(
                !self.0,
                "unsupported content must not read the rest of the file"
            );
            self.0 = true;
            let header = b"opaque bytes";
            buffer[..header.len()].copy_from_slice(header);
            Ok(header.len())
        }
    }
    let report = inspect_reader("huge-opaque.bin", HeaderOnly(false)).unwrap();
    assert!(matches!(report.outcome, FileOutcome::Unsupported));
}

#[test]
fn exemplar_canonicalization_never_interprets_at_inputs() {
    assert_eq!(
        canonical_exemplar("  @/literal path\r\ntext  "),
        "@/literal path\ntext"
    );
    assert_eq!(canonical_exemplar("@-"), "@-");
}

/// A revision selection as `git log` would receive it.
fn revs(spec: &str) -> Vec<String> {
    spec.split_whitespace().map(str::to_owned).collect()
}

struct TestStore {
    _directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
}

impl TestStore {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("posture-test.pile");
        let key = directory.path().join("posture-test.key");
        File::create(&pile).unwrap();
        crate::storage::initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            _directory: directory,
            pile,
            key,
        }
    }

    fn storage(&self) -> PostureStorage<'_> {
        PostureStorage {
            pile: &self.pile,
            key: Some(&self.key),
        }
    }

    fn publish_raw(&self, scope: Id, mut fragment: Fragment, description: &str) {
        fragment.describe_with(entity! { metadata::description: description.to_owned() });
        crate::storage::publish_fragment(&self.pile, Some(&self.key), scope, fragment).unwrap();
    }
}

fn git_fixture(repo: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .env("LC_ALL", "C")
        .env("GIT_AUTHOR_NAME", "Posture Fixture")
        .env("GIT_AUTHOR_EMAIL", "posture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Posture Fixture")
        .env("GIT_COMMITTER_EMAIL", "posture@example.invalid")
        .arg("-C")
        .arg(repo)
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git -C {} {} failed: {}",
        repo.display(),
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn git_audit_fixture() -> tempfile::TempDir {
    // Creating the fixture below the test process's cwd gives us both a
    // genuinely relative spelling and an absolute spelling of one repo.
    let directory = tempfile::Builder::new()
        .prefix("posture-git-")
        .tempdir_in(".")
        .unwrap();
    git_fixture(directory.path(), &["init", "--quiet"]);
    std::fs::write(
        directory.path().join("fixture.txt"),
        "project-sunrise\nproject-sunrise\n",
    )
    .unwrap();
    git_fixture(directory.path(), &["add", "fixture.txt"]);
    git_fixture(
        directory.path(),
        &[
            "commit",
            "--quiet",
            "-m",
            "fixture",
            "-m",
            "project-sunrise\nproject-sunrise",
        ],
    );
    directory
}

fn git_unsafe_attribute_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    git_fixture(directory.path(), &["init", "--quiet"]);
    std::fs::write(
        directory.path().join("schema.rs"),
        concat!(
            "attributes! {\n",
            "    \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" unsafe as legacy: ShortString;\n",
            "}\n",
        ),
    )
    .unwrap();
    git_fixture(directory.path(), &["add", "schema.rs"]);
    git_fixture(
        directory.path(),
        &["commit", "--quiet", "-m", "legacy fixture"],
    );

    std::fs::write(
        directory.path().join("schema.rs"),
        concat!(
            "attributes! {\n",
            "    \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" unsafe as legacy: ShortString;\n",
            "    \"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\" as safe: ShortString;\n",
            "    \"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\" unsafe as pub migrated:\n",
            "        ShortString;\n",
            "    // \"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\" unsafe as prose: ShortString;\n",
            "}\n",
            "const EXPLANATION: &str = \"unsafe as is exceptional\";\n",
        ),
    )
    .unwrap();
    std::fs::write(
        directory.path().join("notes.txt"),
        "\"EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE\" unsafe as not_rust: ShortString;\n",
    )
    .unwrap();
    git_fixture(directory.path(), &["add", "schema.rs", "notes.txt"]);
    git_fixture(
        directory.path(),
        &["commit", "--quiet", "-m", "new declarations"],
    );
    directory
}

fn append_test_term(fragment: &mut Fragment, channel: Id, raw: &str, why: Option<&str>) -> Id {
    let text: TextHandle = fragment.put(canonical_term(raw).unwrap());
    let why: Option<TextHandle> = why.map(|value| fragment.put(value.trim().to_owned()));
    let term = entity! {
        metadata::tag: KIND_TERM,
        posture::in_channel: channel,
        posture::term: text,
        posture::role: EXEMPLAR_PROTECTED,
        posture::why?: why,
    };
    let id = term.root().unwrap();
    *fragment += term;
    id
}

fn append_test_exemplar(
    fragment: &mut Fragment,
    channel: Id,
    raw: &str,
    role: Id,
    vector: Vec<f32>,
) -> Id {
    let text: TextHandle = fragment.put(canonical_exemplar(raw));
    let exemplar = entity! {
        metadata::tag: KIND_EXEMPLAR,
        posture::in_channel: channel,
        posture::term: text,
        posture::role: role,
    };
    let id = exemplar.root().unwrap();
    *fragment += exemplar;
    let embedding = fragment.put(vector);
    *fragment += entity! {
        ExclusiveId::force_ref(&id) @ embeddings::attr::embedding: embedding
    };
    id
}

/// A container-member finding for fixtures. The member is the coordinate's
/// own bytes, which is enough to give each fixture finding a distinct
/// carrier without carrying a real document around.
fn f(modality: Id, field: &str, value: &str) -> Finding {
    member_found(modality, Carrier::member(field.as_bytes()), field, value)
}

fn sample_scan_inputs() -> (Vec<ScannedFile>, Vec<WalkOmission>) {
    (
        vec![
            ScannedFile {
                path: PathBuf::from("examined.png"),
                outcome: FileOutcome::Examined,
                findings: vec![f(modality::EXIF, "EXIF:Artist", "Example Author")],
            },
            ScannedFile {
                path: PathBuf::from("unsupported.bin"),
                outcome: FileOutcome::Unsupported,
                findings: Vec::new(),
            },
            ScannedFile {
                path: PathBuf::from("broken.pdf"),
                outcome: FileOutcome::ParseFailed("malformed fixture".to_owned()),
                findings: Vec::new(),
            },
        ],
        vec![WalkOmission {
            path: PathBuf::from("linked-directory"),
            detail: "directory symlink deliberately not followed".to_owned(),
        }],
    )
}

#[test]
fn canonical_policy_write_and_registered_reads_are_idempotent() {
    let store = TestStore::new();
    let storage = store.storage();

    cmd_vocab_add(
        storage,
        "  Project-Sunrise  ",
        "  Public-Release ",
        Some("  example fixture  "),
    )
    .unwrap();
    let view = storage.policy_view().unwrap();
    assert_eq!(
        storage
            .authored_commits(DEFAULT_POLICY_SCOPE_ID, "policy")
            .unwrap()
            .len(),
        1
    );
    let channel = channel_by_name(&view.reader, &view.facts, "PUBLIC-RELEASE")
        .unwrap()
        .unwrap();
    assert_eq!(
        channel_terms(&view.reader, &view.facts, channel).unwrap(),
        vec![("project-sunrise".to_owned(), "example fixture".to_owned())]
    );
    drop(view);

    // Opening a never-seen scope registers and offers its descriptor
    // closure. That one store operation is distinct from materialization;
    // once registered, repeated snapshots are pure.
    storage.scan_view().unwrap();
    let after_registration = std::fs::metadata(&store.pile).unwrap().len();
    cmd_vocab_add(
        storage,
        "PROJECT-SUNRISE",
        "public-release",
        Some("example fixture"),
    )
    .unwrap();
    assert_eq!(
        std::fs::metadata(&store.pile).unwrap().len(),
        after_registration,
        "an idempotent policy write must not append another COMMIT"
    );

    storage.policy_view().unwrap();
    storage.scan_view().unwrap();
    assert_eq!(
        std::fs::metadata(&store.pile).unwrap().len(),
        after_registration,
        "materializing either registered collection must not mutate the pile"
    );

    let missing_key = store._directory.path().join("missing.key");
    let unavailable = PostureStorage {
        key: Some(&missing_key),
        ..storage
    };
    assert!(unavailable.policy_view().is_err());
    assert!(!missing_key.exists(), "a read must never mint a signer");
    assert_eq!(
        std::fs::metadata(&store.pile).unwrap().len(),
        after_registration
    );
}

#[test]
fn sibling_policy_revisions_remain_visible_and_block_consumers() {
    let store = TestStore::new();
    let mut fragment = Fragment::empty();
    let channel = append_channel(&mut fragment, "public-release");
    let left_term = append_test_term(&mut fragment, channel, "alpha", None);
    let right_term = append_test_term(&mut fragment, channel, "beta", None);
    let base = append_policy_revision(&mut fragment, channel, &BTreeSet::new(), &BTreeSet::new());
    append_policy_revision(
        &mut fragment,
        channel,
        &BTreeSet::from([left_term]),
        &BTreeSet::from([base]),
    );
    append_policy_revision(
        &mut fragment,
        channel,
        &BTreeSet::from([right_term]),
        &BTreeSet::from([base]),
    );
    store.publish_raw(DEFAULT_POLICY_SCOPE_ID, fragment, "forked policy fixture");

    let view = store.storage().policy_view().unwrap();
    match resolve_policy_head(&view.facts, channel).unwrap() {
        PolicyHead::Forked(heads) => assert_eq!(heads.len(), 2),
        other => panic!("expected visible policy fork, got {other:?}"),
    }
    drop(view);
    let error = load_terms(store.storage(), "public-release").unwrap_err();
    assert!(error.to_string().contains("FORKED"));
}

#[test]
fn one_revision_preserves_parallel_annotations_of_the_same_term() {
    let store = TestStore::new();
    let mut fragment = Fragment::empty();
    let channel = append_channel(&mut fragment, "public-release");
    let old = append_test_term(&mut fragment, channel, "alpha", Some("old rationale"));
    let new = append_test_term(&mut fragment, channel, "alpha", Some("new rationale"));
    append_policy_revision(
        &mut fragment,
        channel,
        &BTreeSet::from([old, new]),
        &BTreeSet::new(),
    );
    store.publish_raw(
        DEFAULT_POLICY_SCOPE_ID,
        fragment,
        "ambiguous policy fixture",
    );

    let view = store.storage().policy_view().unwrap();
    assert_eq!(
        channel_terms(&view.reader, &view.facts, channel)
            .unwrap()
            .into_iter()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            ("alpha".to_owned(), "old rationale".to_owned()),
            ("alpha".to_owned(), "new rationale".to_owned()),
        ])
    );
}

#[test]
fn exemplar_identity_excludes_embedding_exhaust_and_role_changes_replace_membership() {
    let store = TestStore::new();
    let mut first = Fragment::empty();
    let channel = append_channel(&mut first, "public-release");
    let exemplar = append_test_exemplar(
        &mut first,
        channel,
        "A generic protected example passage.",
        EXEMPLAR_PROTECTED,
        vec![0.0; 768],
    );
    append_policy_revision(
        &mut first,
        channel,
        &BTreeSet::from([exemplar]),
        &BTreeSet::new(),
    );
    store.publish_raw(DEFAULT_POLICY_SCOPE_ID, first, "first exemplar exhaust");

    let mut second = Fragment::empty();
    let second_channel = append_channel(&mut second, "public-release");
    let same_exemplar = append_test_exemplar(
        &mut second,
        second_channel,
        "A generic protected example passage.",
        EXEMPLAR_PROTECTED,
        vec![1.0; 768],
    );
    assert_eq!(channel, second_channel);
    assert_eq!(exemplar, same_exemplar);
    store.publish_raw(
        DEFAULT_POLICY_SCOPE_ID,
        second,
        "replacement exemplar exhaust",
    );

    let view = store.storage().policy_view().unwrap();
    let roles = find!(
        role: Id,
        pattern!(&view.facts, [{ (exemplar) @ posture::role: ?role }])
    )
    .collect::<BTreeSet<_>>();
    assert_eq!(roles, BTreeSet::from([EXEMPLAR_PROTECTED]));
    let vectors = find!(
        vector: Inline<inlineencodings::Handle<Embedding768>>,
        pattern!(&view.facts, [{
            (exemplar) @ embeddings::attr::embedding: ?vector
        }])
    )
    .collect::<BTreeSet<_>>();
    assert_eq!(
        vectors.len(),
        2,
        "embedding versions are retained as exhaust"
    );

    let (head, mut members) = policy_members(&view.facts, channel).unwrap();
    let removed = take_exemplars_with_body(
        &view.reader,
        &view.facts,
        &mut members,
        "A generic protected example passage.",
    )
    .unwrap();
    assert_eq!(removed, BTreeSet::from([exemplar]));
    assert!(!members.contains(&exemplar));
    drop(view);

    let mut role_change = Fragment::empty();
    let role_channel = append_channel(&mut role_change, "public-release");
    let benign = append_test_exemplar(
        &mut role_change,
        role_channel,
        "A generic protected example passage.",
        EXEMPLAR_BENIGN,
        vec![0.5; 768],
    );
    members.insert(benign);
    append_policy_revision(
        &mut role_change,
        role_channel,
        &members,
        &head.into_iter().collect(),
    );
    store.publish_raw(DEFAULT_POLICY_SCOPE_ID, role_change, "exemplar role change");
    let view = store.storage().policy_view().unwrap();
    let (_, current) = policy_members(&view.facts, channel).unwrap();
    assert!(current.contains(&benign));
    assert!(!current.contains(&exemplar));

    let invalid = TestStore::new();
    let mut ambiguous = Fragment::empty();
    let channel = append_channel(&mut ambiguous, "public-release");
    let protected = append_test_exemplar(
        &mut ambiguous,
        channel,
        "One passage cannot occupy both policy roles.",
        EXEMPLAR_PROTECTED,
        vec![0.0; 768],
    );
    let benign = append_test_exemplar(
        &mut ambiguous,
        channel,
        "One passage cannot occupy both policy roles.",
        EXEMPLAR_BENIGN,
        vec![1.0; 768],
    );
    append_policy_revision(
        &mut ambiguous,
        channel,
        &BTreeSet::from([protected, benign]),
        &BTreeSet::new(),
    );
    invalid.publish_raw(
        DEFAULT_POLICY_SCOPE_ID,
        ambiguous,
        "ambiguous exemplar roles",
    );
    let view = invalid.storage().policy_view().unwrap();
    let (_, members) = policy_members(&view.facts, channel).unwrap();
    assert_eq!(members, BTreeSet::from([protected, benign]));
}

#[test]
fn complete_scan_is_one_atomic_commit_with_explicit_outcomes_and_omissions() {
    let store = TestStore::new();
    let created_at = point_interval(Epoch::from_unix_seconds(1_234.0));
    let (files, omissions) = sample_scan_inputs();
    let (fragment, scan) = build_scan_fragment(
        Path::new("fixture-corpus"),
        &files,
        &omissions,
        created_at,
        None,
        IMPLEMENTED.iter().copied().collect(),
    );
    assert_eq!(
        validate_scan_commit_fragment(fragment.facts()).unwrap(),
        scan
    );
    store
        .storage()
        .publish_scan(fragment, "complete scan fixture")
        .unwrap();

    let view = store.storage().scan_view().unwrap();
    assert_eq!(
        store
            .storage()
            .authored_commits(DEFAULT_SCAN_SCOPE_ID, "scan")
            .unwrap()
            .len(),
        1
    );
    let outcomes = find!(
        outcome: Id,
        pattern!(&view.facts, [{
            _?document @ metadata::tag: (&KIND_DOCUMENT), posture::outcome: ?outcome
        }])
    )
    .collect::<BTreeSet<_>>();
    assert_eq!(
        outcomes,
        BTreeSet::from([OUTCOME_EXAMINED, DOC_UNSUPPORTED, OUTCOME_PARSE_FAILED])
    );
    assert_eq!(
        find!(
            omission: Id,
            pattern!(&view.facts, [{ ?omission @ metadata::tag: (&KIND_OMISSION) }])
        )
        .count(),
        1
    );
    drop(view);

    // The same observation signed twice remains one payload member with
    // two provenance fibers. Collection set semantics, not a racy
    // check-before-append, collapse the duplicate data.
    let (files, omissions) = sample_scan_inputs();
    let (duplicate, duplicate_scan) = build_scan_fragment(
        Path::new("fixture-corpus"),
        &files,
        &omissions,
        created_at,
        None,
        IMPLEMENTED.iter().copied().collect(),
    );
    assert_eq!(scan, duplicate_scan);

    let (mut changed_files, omissions) = sample_scan_inputs();
    changed_files[0].findings[0].value = "Different Author".to_owned();
    let (_, changed_scan) = build_scan_fragment(
        Path::new("fixture-corpus"),
        &changed_files,
        &omissions,
        created_at,
        None,
        IMPLEMENTED.iter().copied().collect(),
    );
    assert_ne!(
        scan, changed_scan,
        "changing evidence under an otherwise identical header must change the Merkle root"
    );

    store
        .storage()
        .publish_scan(duplicate, "duplicate scan fixture")
        .unwrap();
    let view = store.storage().scan_view().unwrap();
    assert_eq!(all_scan_ids(&view.facts), BTreeSet::from([scan]));
}

#[test]
fn git_only_modality_preserves_historical_file_scan_coverage() {
    let created_at = point_interval(Epoch::from_unix_seconds(1_500.0));
    let (files, omissions) = sample_scan_inputs();
    let (historical, historical_scan) = build_scan_fragment(
        Path::new("historical-file-scan"),
        &files,
        &omissions,
        created_at,
        None,
        IMPLEMENTED.iter().copied().collect(),
    );
    assert_eq!(
        validate_scan_commit_fragment(historical.facts()).unwrap(),
        historical_scan
    );
    assert!(!exists!(pattern!(historical.facts(), [{
        (historical_scan) @ posture::unchecked: (&modality::UNSAFE_ATTRIBUTE_ID)
    }])));

    let files = [ScannedFile {
        path: PathBuf::from("repository"),
        outcome: FileOutcome::Examined,
        findings: vec![f(
            modality::UNSAFE_ATTRIBUTE_ID,
            "rust-attribute-added src/schema.rs#1",
            UNSAFE_ATTRIBUTE_FINDING,
        )],
    }];
    let (git, git_scan) = build_scan_fragment(
        Path::new("git:repository HEAD"),
        &files,
        &[],
        point_interval(Epoch::from_unix_seconds(1_501.0)),
        None,
        BTreeSet::from([modality::PROTECTED_TERM, modality::UNSAFE_ATTRIBUTE_ID]),
    );
    assert_eq!(
        validate_scan_commit_fragment(git.facts()).unwrap(),
        git_scan
    );
    assert!(exists!(pattern!(git.facts(), [{
        _?finding @ metadata::tag: (&KIND_FINDING), metadata::tag: (&modality::UNSAFE_ATTRIBUTE_ID)
    }])));
}

#[test]
fn scan_structure_rejects_incomplete_and_semantically_inconsistent_records() {
    let target = Path::new("fixture-corpus");
    let created_at = point_interval(Epoch::from_unix_seconds(2_345.0));

    let mut missing_coverage = Fragment::empty();
    let target_handle: TextHandle = missing_coverage.put(target.display().to_string());
    missing_coverage += entity! {
        metadata::tag: KIND_SCAN,
        metadata::created_at: created_at,
        posture::target: target_handle,
        posture::file_count: 0_u64,
        posture::checked*: BTreeSet::from([modality::EXIF]),
        posture::unchecked*: BTreeSet::<Id>::new(),
    };
    assert!(validate_scan_commit_fragment(missing_coverage.facts())
        .unwrap_err()
        .to_string()
        .contains("partition every file-scan coverage modality"));

    let mut missing_document = Fragment::empty();
    let target_handle: TextHandle = missing_document.put(target.display().to_string());
    missing_document += entity! {
        metadata::tag: KIND_SCAN,
        metadata::created_at: created_at,
        posture::target: target_handle,
        posture::file_count: 1_u64,
        posture::checked*: IMPLEMENTED.iter().copied().collect::<BTreeSet<_>>(),
        posture::unchecked*: unchecked_modalities(),
    };
    assert!(validate_scan_commit_fragment(missing_document.facts())
        .unwrap_err()
        .to_string()
        .contains("file_count"));

    let mut no_detail = Fragment::empty();
    let target_handle: TextHandle = no_detail.put(target.display().to_string());
    let path: TextHandle = no_detail.put("broken.pdf".to_owned());
    let document = entity! {
        metadata::tag: KIND_DOCUMENT,
        posture::path: path,
        posture::outcome: OUTCOME_PARSE_FAILED,
    };
    let document_id = document.root().unwrap();
    let scan_entity = entity! {
        metadata::tag: KIND_SCAN,
        metadata::created_at: created_at,
        posture::target: target_handle,
        posture::file_count: 1_u64,
        posture::checked*: IMPLEMENTED.iter().copied().collect::<BTreeSet<_>>(),
        posture::unchecked*: unchecked_modalities(),
        posture::scan_document*: BTreeSet::from([document_id]),
    };
    no_detail += document;
    no_detail += scan_entity;
    assert!(validate_scan_commit_fragment(no_detail.facts())
        .unwrap_err()
        .to_string()
        .contains("parse-failure detail"));

    let files = vec![ScannedFile {
        path: PathBuf::from("examined.png"),
        outcome: FileOutcome::Examined,
        findings: vec![f(modality::EXIF, "EXIF:Artist", "Example Author")],
    }];
    let (left, _) = build_scan_fragment(
        target,
        &files,
        &[],
        created_at,
        None,
        IMPLEMENTED.iter().copied().collect(),
    );
    let files = vec![ScannedFile {
        path: PathBuf::from("examined.png"),
        outcome: FileOutcome::Examined,
        findings: Vec::new(),
    }];
    let (right, _) = build_scan_fragment(
        target,
        &files,
        &[],
        point_interval(Epoch::from_unix_seconds(2_346.0)),
        None,
        IMPLEMENTED.iter().copied().collect(),
    );
    let mut mixed = left.into_facts();
    mixed += right.into_facts();
    assert!(validate_scan_commit_fragment(&mixed)
        .unwrap_err()
        .to_string()
        .contains("scan COMMIT root"));
}

#[test]
fn semantic_occurrences_are_settled_directly_by_exact_decide_outcomes() {
    let store = TestStore::new();
    let storage = store.storage();
    let (files, omissions) = sample_scan_inputs();
    let (first, first_scan) = build_scan_fragment(
        Path::new("fixture-corpus"),
        &files,
        &omissions,
        point_interval(Epoch::from_unix_seconds(3_000.0)),
        None,
        IMPLEMENTED.iter().copied().collect(),
    );
    let occurrence = one_required(
        find!(
            finding: Id,
            pattern!(first.facts(), [{ ?finding @ metadata::tag: (&KIND_FINDING) }])
        )
        .collect(),
        "fixture finding",
    )
    .unwrap();
    storage.publish_scan(first, "first semantic scan").unwrap();

    let (second, second_scan) = build_scan_fragment(
        Path::new("fixture-corpus"),
        &files,
        &omissions,
        point_interval(Epoch::from_unix_seconds(3_001.0)),
        None,
        IMPLEMENTED.iter().copied().collect(),
    );
    assert_ne!(first_scan, second_scan);
    // The same material, observed again: one finding, two sightings.
    assert!(exists!(pattern!(second.facts(), [{
        (occurrence) @ metadata::tag: (&KIND_FINDING)
    }])));
    storage
        .publish_scan(second, "second semantic scan")
        .unwrap();

    let decision = genid().id;
    let proposed = decide::decision_fragment(
        decision,
        "Classify this Posture occurrence",
        None,
        Some(occurrence),
        point_interval(Epoch::from_unix_seconds(3_002.0)),
    )
    .unwrap()
    .0;
    store.publish_raw(
        DEFAULT_DECIDE_SCOPE_ID,
        proposed,
        "unresolved fixture decision",
    );
    let view = storage.decide_view().unwrap();
    assert!(!benign_occurrences(&view.reader, &view.facts)
        .unwrap()
        .contains(&occurrence));

    let benign = decide::resolution_fragment(
        decision,
        "benign, and here is a whole sentence of reasoning about why",
        Some(decide::RESULT_BENIGN),
        true,
        &[],
        &[],
        point_interval(Epoch::from_unix_seconds(3_003.0)),
    )
    .unwrap()
    .0;
    store.publish_raw(DEFAULT_DECIDE_SCOPE_ID, benign, "benign fixture decision");
    let view = storage.decide_view().unwrap();
    assert!(benign_occurrences(&view.reader, &view.facts)
        .unwrap()
        .contains(&occurrence));

    let disagreement = genid().id;
    let proposed = decide::decision_fragment(
        disagreement,
        "Reconsider this Posture occurrence",
        None,
        Some(occurrence),
        point_interval(Epoch::from_unix_seconds(3_004.0)),
    )
    .unwrap()
    .0;
    store.publish_raw(DEFAULT_DECIDE_SCOPE_ID, proposed, "second fixture decision");
    let other = decide::resolution_fragment(
        disagreement,
        "sensitive",
        None,
        true,
        &[],
        &[],
        point_interval(Epoch::from_unix_seconds(3_005.0)),
    )
    .unwrap()
    .0;
    store.publish_raw(
        DEFAULT_DECIDE_SCOPE_ID,
        other,
        "disagreeing fixture decision",
    );
    let view = storage.decide_view().unwrap();
    assert!(!benign_occurrences(&view.reader, &view.facts)
        .unwrap()
        .contains(&occurrence));
}

#[test]
fn agreed_benign_heads_settle_but_a_fork_does_not() {
    let store = TestStore::new();
    let decision = genid().id;
    let occurrence = genid().id;
    store.publish_raw(
        DEFAULT_DECIDE_SCOPE_ID,
        decide::decision_fragment(
            decision,
            "Classify occurrence",
            None,
            Some(occurrence),
            point_interval(Epoch::from_unix_seconds(4_000.0)),
        )
        .unwrap()
        .0,
        "fixture decision",
    );
    store.publish_raw(
        DEFAULT_DECIDE_SCOPE_ID,
        decide::resolution_fragment(
            decision,
            "benign, and here is a whole sentence of reasoning about why",
            Some(decide::RESULT_BENIGN),
            true,
            &[],
            &[],
            point_interval(Epoch::from_unix_seconds(4_001.0)),
        )
        .unwrap()
        .0,
        "first benign head",
    );
    store.publish_raw(
        DEFAULT_DECIDE_SCOPE_ID,
        decide::resolution_fragment(
            decision,
            "benign, and here is a whole sentence of reasoning about why",
            Some(decide::RESULT_BENIGN),
            true,
            &[],
            &[],
            point_interval(Epoch::from_unix_seconds(4_002.0)),
        )
        .unwrap()
        .0,
        "second benign head",
    );
    let view = store.storage().decide_view().unwrap();
    assert!(matches!(
        decide::resolution(&view.facts, decision),
        Resolution::Agreed(_)
    ));
    assert!(benign_occurrences(&view.reader, &view.facts)
        .unwrap()
        .contains(&occurrence));

    store.publish_raw(
        DEFAULT_DECIDE_SCOPE_ID,
        decide::resolution_fragment(
            decision,
            "reject",
            None,
            true,
            &[],
            &[],
            point_interval(Epoch::from_unix_seconds(4_003.0)),
        )
        .unwrap()
        .0,
        "rejecting head",
    );
    let view = store.storage().decide_view().unwrap();
    assert!(matches!(
        decide::resolution(&view.facts, decision),
        Resolution::Forked(_)
    ));
    assert!(!benign_occurrences(&view.reader, &view.facts)
        .unwrap()
        .contains(&occurrence));
}

/// The two hooks do different jobs, and the difference has to be real in
/// the generated scripts, not only in the documentation.
#[test]
fn the_gate_refuses_and_the_smoke_alarm_never_does() {
    let store = TestStore::new();
    let repo = git_audit_fixture();
    let hooks = repo.path().join(".git").join("hooks");

    install_hooks(
        store.storage(),
        repo.path(),
        Path::new("posture-fixture"),
        "github-public",
        Some("example"),
        false,
        false,
    )
    .unwrap();

    let pre_push = std::fs::read_to_string(hooks.join("pre-push")).unwrap();
    let post_commit = std::fs::read_to_string(hooks.join("post-commit")).unwrap();

    // Neither flag installs both: they are two halves of one habit.
    assert!(pre_push.contains("Installed by `posture hook`"));
    assert!(post_commit.contains("Installed by `posture hook`"));

    // The gate reads what the push ADDS, and refuses.
    assert!(pre_push.contains("--not $already_there"));
    assert!(pre_push.contains("exit $status"));
    assert!(pre_push.contains("Refusing the push"));

    // The alarm reads the commit that just happened, and cannot refuse:
    // every exit it can reach is zero, including the one where its own
    // tooling is missing.
    assert!(post_commit.contains("HEAD --not HEAD^@"));
    // It must not make anyone WAIT either: one pile open is 142s of CPU,
    // and a commit that pauses for two minutes is a commit nobody makes.
    assert!(
        post_commit.contains("| tee -a \"$LOG\" &"),
        "the audit has to run detached or the hook is unusable on a real pile"
    );
    assert!(post_commit.contains("mkdir \"$LOCK\""));
    assert!(
        !post_commit.contains("exit 1"),
        "a post-commit hook that exits non-zero changes nothing git does and \
         only trains the reader to ignore it"
    );
    // A destination it cannot know must not silently narrow what it reads.
    assert!(!post_commit.contains("REMOTE_MATCH"));

    // Naming one hook is a deliberate restriction. Install into a second
    // repo so this is not confused with the pair written above.
    let single = git_audit_fixture();
    install_hooks(
        store.storage(),
        single.path(),
        Path::new("posture-fixture"),
        "github-public",
        None,
        false,
        true,
    )
    .unwrap();
    let single_hooks = single.path().join(".git").join("hooks");
    assert!(single_hooks.join("post-commit").exists());
    assert!(!single_hooks.join("pre-push").exists());
}

/// A hook someone else wrote is not ours to overwrite, and that has to hold
/// for every hook posture installs, not only the first one it learned.
#[test]
fn a_foreign_hook_of_either_name_is_never_clobbered() {
    let store = TestStore::new();
    for name in ["pre-push", "post-commit"] {
        let repo = git_audit_fixture();
        let hooks = repo.path().join(".git").join("hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        std::fs::write(hooks.join(name), "#!/bin/sh\n# someone else's\n").unwrap();
        let error = install_hooks(
            store.storage(),
            repo.path(),
            Path::new("posture-fixture"),
            "github-public",
            None,
            false,
            false,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("not written by posture"),
            "{name}: {error}"
        );
        assert_eq!(
            std::fs::read_to_string(hooks.join(name)).unwrap(),
            "#!/bin/sh\n# someone else's\n"
        );
    }
}

#[test]
fn posture_cli_has_no_parallel_verdict_commands() {
    let command = Cli::command();
    for retired in ["accept", "defer", "revoke"] {
        assert!(command.find_subcommand(retired).is_none());
    }
}

#[test]
fn foreign_scan_commits_are_stored_but_inert_without_write_admission() {
    let store = TestStore::new();
    let (files, omissions) = sample_scan_inputs();
    let (fragment, _) = build_scan_fragment(
        Path::new("foreign-corpus"),
        &files,
        &omissions,
        point_interval(Epoch::from_unix_seconds(4_000.0)),
        None,
        IMPLEMENTED.iter().copied().collect(),
    );
    let mut pile = open_pile_strict(&store.pile).unwrap();
    let local = crate::storage::load_signer(&store.pile, Some(&store.key)).unwrap();
    let collection =
        open_configured(&mut pile, DEFAULT_SCAN_SCOPE_ID, local.verifying_key()).unwrap();
    let foreign = ed25519_dalek::SigningKey::from_bytes(&[0x91; 32]);
    // Publication is an unconditional local ledger append. Admission is a
    // separate read concern rooted in this collection's immutable WRITE
    // admission policy.
    let foreign_commit = pile.commit(collection, &foreign, fragment).unwrap();
    pile.close().unwrap();

    let view = store.storage().scan_view().unwrap();
    assert!(all_scan_ids(&view.facts).is_empty());
    assert!(store
        .storage()
        .authored_commits(DEFAULT_SCAN_SCOPE_ID, "scan")
        .unwrap()
        .is_empty());

    let mut pile = open_pile_strict(&store.pile).unwrap();
    let store_snapshot = pile.snapshot().unwrap();
    let records =
        triblespace::core::collection::discover_collection_records(&store_snapshot).unwrap();
    let stored = records
        .commits()
        .iter()
        .copied()
        .filter(|commit| commit.collection() == collection.handle())
        .collect::<Vec<_>>();
    assert_eq!(stored, vec![foreign_commit]);
    pile.close().unwrap();
}

#[test]
fn unauthorized_duplicate_claim_does_not_poison_scan_atomicity() {
    let store = TestStore::new();
    let created_at = point_interval(Epoch::from_unix_seconds(4_100.0));
    let (files, omissions) = sample_scan_inputs();
    let (fragment, first_scan) = build_scan_fragment(
        Path::new("duplicate-author-corpus"),
        &files,
        &omissions,
        created_at,
        None,
        IMPLEMENTED.iter().copied().collect(),
    );
    let admitted = store
        .storage()
        .publish_scan(fragment.clone(), "admitted scan")
        .unwrap();

    let mut pile = open_pile_strict(&store.pile).unwrap();
    let local = crate::storage::load_signer(&store.pile, Some(&store.key)).unwrap();
    let collection =
        open_configured(&mut pile, DEFAULT_SCAN_SCOPE_ID, local.verifying_key()).unwrap();
    let foreign = ed25519_dalek::SigningKey::from_bytes(&[0x92; 32]);
    let duplicate = pile.commit(collection, &foreign, fragment).unwrap();
    assert_eq!(duplicate.data(), admitted.data());
    pile.close().unwrap();

    // A later write validates the exact admission roots of its snapshot,
    // not every currently resident signature over the same payload.
    let (mut changed_files, omissions) = sample_scan_inputs();
    changed_files[0].findings[0].value = "Independent observation".to_owned();
    let (next, next_scan) = build_scan_fragment(
        Path::new("duplicate-author-corpus"),
        &changed_files,
        &omissions,
        point_interval(Epoch::from_unix_seconds(4_101.0)),
        None,
        IMPLEMENTED.iter().copied().collect(),
    );
    assert_ne!(next_scan, first_scan);
    store
        .storage()
        .publish_scan(next, "next admitted scan")
        .unwrap();

    assert_eq!(
        store
            .storage()
            .authored_commits(DEFAULT_SCAN_SCOPE_ID, "scan")
            .unwrap()
            .len(),
        2,
    );
}

#[test]
fn additive_legacy_policy_facts_are_inert_beside_canonical_shadows() {
    let store = TestStore::new();
    let mut fragment = Fragment::empty();
    let old_channel = ExclusiveId::force(Id::new([0x92; 16]).unwrap());
    let name: TextHandle = fragment.put("public-release".to_owned());
    fragment += entity! { &old_channel @
        metadata::tag: KIND_CHANNEL,
        posture::channel_name: name,
    };
    let old_term = ExclusiveId::force(Id::new([0x93; 16]).unwrap());
    let text: TextHandle = fragment.put("legacy-term".to_owned());
    fragment += entity! { &old_term @
        metadata::tag: KIND_TERM,
        posture::in_channel: &old_channel,
        posture::term: text,
    };

    let channel = append_channel(&mut fragment, "public-release");
    let term = append_test_term(&mut fragment, channel, "legacy-term", None);
    append_policy_revision(
        &mut fragment,
        channel,
        &BTreeSet::from([term]),
        &BTreeSet::new(),
    );
    store.publish_raw(DEFAULT_POLICY_SCOPE_ID, fragment, "additive policy fixture");

    let view = store.storage().policy_view().unwrap();
    assert_eq!(
        channel_by_name(&view.reader, &view.facts, "public-release").unwrap(),
        Some(channel)
    );
    assert_ne!(*old_channel, channel);
    assert!(exists!(pattern!(&view.facts, [{
        (*old_term) @ metadata::tag: (&KIND_TERM)
    }])));
    assert_eq!(
        channel_terms(&view.reader, &view.facts, channel).unwrap(),
        vec![("legacy-term".to_owned(), String::new())]
    );
    drop(view);

    let unknown = entity! { metadata::tag: genid().id };
    store.publish_raw(
        DEFAULT_POLICY_SCOPE_ID,
        unknown,
        "unrecognized policy fixture",
    );
    let view = store.storage().policy_view().unwrap();
    assert_eq!(
        channel_terms(&view.reader, &view.facts, channel).unwrap(),
        vec![("legacy-term".to_owned(), String::new())]
    );
}

#[test]
fn git_occurrences_are_independent_of_repo_path_spelling() {
    let directory = git_audit_fixture();
    let relative = PathBuf::from(directory.path().file_name().unwrap());
    assert!(relative.is_relative());
    let absolute = std::fs::canonicalize(directory.path()).unwrap();
    let terms = vec![("project-sunrise".to_owned(), "fixture".to_owned())];

    let from_relative = collect_hits(&relative, &revs("HEAD"), &terms).unwrap();
    let from_absolute = collect_hits(&absolute, &revs("HEAD"), &terms).unwrap();

    assert_eq!(from_relative.repo_root, absolute);
    assert_eq!(from_absolute.repo_root, absolute);
    assert_eq!(from_relative.hits, from_absolute.hits);
    let relative_ids = from_relative.hits["project-sunrise"]
        .iter()
        .map(|hit| finding_id(modality::PROTECTED_TERM, &hit.location))
        .collect::<Vec<_>>();
    let absolute_ids = from_absolute.hits["project-sunrise"]
        .iter()
        .map(|hit| finding_id(modality::PROTECTED_TERM, &hit.location))
        .collect::<Vec<_>>();
    assert_eq!(relative_ids, absolute_ids);
}

#[test]
fn git_unsafe_attribute_rule_checks_only_new_literal_pins_in_rust() {
    let directory = git_unsafe_attribute_fixture();
    let audit = collect_hits(directory.path(), &revs("HEAD^..HEAD"), &[]).unwrap();

    assert!(audit.hits.is_empty());
    assert_eq!(audit.unsafe_attribute_hits.len(), 1);
    let hit = &audit.unsafe_attribute_hits[0];
    assert!(hit.evidence.contains("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"));
    assert!(hit.evidence.contains("ShortString;"));
    assert!(hit.evidence.contains("schema.rs"));

    let whole_history = collect_hits(directory.path(), &revs("HEAD"), &[]).unwrap();
    assert_eq!(
        whole_history.unsafe_attribute_hits.len(),
        2,
        "the old literal pin is visible only when its introducing commit is in range"
    );
}

#[test]
fn git_unsafe_attribute_invariant_runs_but_a_missing_lexical_channel_fails_closed() {
    let store = TestStore::new();
    assert!(load_channel_terms(store.storage(), "undefined-channel")
        .unwrap()
        .is_none());

    let directory = git_unsafe_attribute_fixture();
    let audit = collect_hits(directory.path(), &revs("HEAD^..HEAD"), &[]).unwrap();
    assert!(audit.hits.is_empty());
    assert_eq!(audit.unsafe_attribute_hits.len(), 1);
    assert!(git_audit_must_fail(
        false,
        0,
        audit.unsafe_attribute_hits.len()
    ));
    assert!(
        git_audit_must_fail(false, 0, 0),
        "a quiet invariant scan must not disguise missing lexical coverage"
    );
}

#[test]
fn unsafe_attribute_parser_accepts_token_tree_header_wrapping_and_comments() {
    let declarations = unsafe_attribute_declarations(concat!(
        "attributes! {\n",
        "    \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n",
        "    /* compatibility arm */ unsafe\n",
        "    // macro keyword follows\n",
        "    as legacy:\n",
        "        inlineencodings::GenId;\n",
        "}\n",
    ));
    assert_eq!(declarations.len(), 1);
    assert_eq!(declarations[0].start_line, 2);
    assert_eq!(declarations[0].end_line, 6);
    assert!(declarations[0].text.contains("inlineencodings::GenId;"));

    let after_as_comment = unsafe_attribute_declarations(concat!(
        "attributes! {\n",
        "    \"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\" unsafe as value:\n",
        "        /* preserved for compatibility; do not change */\n",
        "        inlineencodings::GenId;\n",
        "}\n",
    ));
    assert_eq!(after_as_comment.len(), 1);
    assert!(after_as_comment[0]
        .text
        .contains("compatibility; do not change"));
    assert!(after_as_comment[0].text.contains("inlineencodings::GenId;"));
}

#[test]
fn multiline_encoding_only_change_is_a_new_unsafe_attribute_occurrence() {
    let directory = git_unsafe_attribute_fixture();
    let before = collect_hits(directory.path(), &revs("HEAD^..HEAD"), &[]).unwrap();
    assert_eq!(before.unsafe_attribute_hits.len(), 1);
    let before_id = finding_id(
        modality::UNSAFE_ATTRIBUTE_ID,
        &before.unsafe_attribute_hits[0].location,
    );

    let path = directory.path().join("schema.rs");
    let source = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        source.replace("        ShortString;", "        inlineencodings::GenId;"),
    )
    .unwrap();
    git_fixture(directory.path(), &["add", "schema.rs"]);
    git_fixture(
        directory.path(),
        &["commit", "--quiet", "-m", "change pinned encoding"],
    );

    let after = collect_hits(directory.path(), &revs("HEAD^..HEAD"), &[]).unwrap();
    assert_eq!(after.unsafe_attribute_hits.len(), 2);
    let added = after
        .unsafe_attribute_hits
        .iter()
        .find(|hit| hit.evidence.starts_with("rust-attribute-added"))
        .unwrap();
    let removed = after
        .unsafe_attribute_hits
        .iter()
        .find(|hit| hit.evidence.starts_with("rust-attribute-removed"))
        .unwrap();
    assert!(added.evidence.contains("inlineencodings::GenId;"));
    assert!(removed.evidence.contains("ShortString;"));
    assert_ne!(
        before_id,
        finding_id(modality::UNSAFE_ATTRIBUTE_ID, &added.location),
        "the encoding is part of the exact compatibility claim"
    );
}

#[test]
fn unsafe_attribute_removal_unpinning_and_renaming_are_reviewed() {
    let unpinned = git_unsafe_attribute_fixture();
    let path = unpinned.path().join("schema.rs");
    let source = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        source.replace("unsafe as pub migrated", "as pub migrated"),
    )
    .unwrap();
    git_fixture(unpinned.path(), &["add", "schema.rs"]);
    git_fixture(
        unpinned.path(),
        &["commit", "--quiet", "-m", "use safe attribute anchor"],
    );
    let audit = collect_hits(unpinned.path(), &revs("HEAD^..HEAD"), &[]).unwrap();
    assert_eq!(audit.unsafe_attribute_hits.len(), 1);
    assert!(audit.unsafe_attribute_hits[0]
        .evidence
        .starts_with("rust-attribute-removed"));
    assert!(audit.unsafe_attribute_hits[0]
        .evidence
        .contains("pub migrated"));

    let renamed = git_unsafe_attribute_fixture();
    let path = renamed.path().join("schema.rs");
    let source = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, source.replace("pub migrated", "pub renamed")).unwrap();
    git_fixture(renamed.path(), &["add", "schema.rs"]);
    git_fixture(
        renamed.path(),
        &["commit", "--quiet", "-m", "rename pinned attribute"],
    );
    let audit = collect_hits(renamed.path(), &revs("HEAD^..HEAD"), &[]).unwrap();
    assert_eq!(audit.unsafe_attribute_hits.len(), 2);
    assert!(audit
        .unsafe_attribute_hits
        .iter()
        .any(|hit| hit.evidence.starts_with("rust-attribute-added")
            && hit.evidence.contains("pub renamed")));
    assert!(audit
        .unsafe_attribute_hits
        .iter()
        .any(|hit| hit.evidence.starts_with("rust-attribute-removed")
            && hit.evidence.contains("pub migrated")));
}

#[test]
fn whitespace_only_unsafe_attribute_rewrite_reuses_justification() {
    let directory = git_unsafe_attribute_fixture();
    let path = directory.path().join("schema.rs");
    let source = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        source.replace(
            "\"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\" unsafe as pub migrated:\n        ShortString;",
            "\"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\" unsafe as pub migrated: ShortString;",
        ),
    )
    .unwrap();
    git_fixture(directory.path(), &["add", "schema.rs"]);
    git_fixture(
        directory.path(),
        &["commit", "--quiet", "-m", "format schema"],
    );
    let audit = collect_hits(directory.path(), &revs("HEAD^..HEAD"), &[]).unwrap();
    assert!(
        audit.unsafe_attribute_hits.is_empty(),
        "a source-only rewrite of the same path/name/encoding claim keeps its decision"
    );
}

#[test]
fn merge_audits_removal_relative_only_to_non_first_parent() {
    let directory = tempfile::tempdir().unwrap();
    git_fixture(directory.path(), &["init", "--quiet"]);
    std::fs::write(directory.path().join("schema.rs"), "attributes! {}\n").unwrap();
    git_fixture(directory.path(), &["add", "schema.rs"]);
    git_fixture(directory.path(), &["commit", "--quiet", "-m", "base"]);
    let main_branch = git_fixture(directory.path(), &["branch", "--show-current"]);

    git_fixture(directory.path(), &["checkout", "--quiet", "-b", "side"]);
    std::fs::write(
        directory.path().join("schema.rs"),
        concat!(
            "attributes! {\n",
            "    \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" unsafe as side_pin: ShortString;\n",
            "}\n",
        ),
    )
    .unwrap();
    git_fixture(directory.path(), &["add", "schema.rs"]);
    git_fixture(
        directory.path(),
        &["commit", "--quiet", "-m", "side adds pin"],
    );

    git_fixture(directory.path(), &["checkout", "--quiet", &main_branch]);
    std::fs::write(directory.path().join("main.txt"), "main work\n").unwrap();
    git_fixture(directory.path(), &["add", "main.txt"]);
    git_fixture(directory.path(), &["commit", "--quiet", "-m", "main work"]);
    git_fixture(
        directory.path(),
        &[
            "merge",
            "--quiet",
            "--no-ff",
            "-s",
            "ours",
            "side",
            "-m",
            "merge without side pin",
        ],
    );

    let merge = git_fixture(directory.path(), &["rev-parse", "HEAD"]);
    let lineage = git_fixture(
        directory.path(),
        &["rev-list", "--parents", "-n", "1", &merge],
    );
    let parents = lineage.split_whitespace().skip(1).collect::<Vec<_>>();
    assert_eq!(parents.len(), 2);
    let mut unsafe_hits = Vec::new();
    collect_parent_unsafe_hits(directory.path(), &merge, Some(parents[1]), &mut unsafe_hits)
        .unwrap();
    assert_eq!(unsafe_hits.len(), 1);
    let hit = &unsafe_hits[0];
    assert!(hit.evidence.starts_with("rust-attribute-removed"));
    assert!(hit.evidence.contains("side_pin: ShortString;"));
}

#[test]
fn merge_deduplicates_one_new_claim_seen_against_both_parents() {
    let directory = tempfile::tempdir().unwrap();
    git_fixture(directory.path(), &["init", "--quiet"]);
    std::fs::write(directory.path().join("schema.rs"), "attributes! {}\n").unwrap();
    git_fixture(directory.path(), &["add", "schema.rs"]);
    git_fixture(directory.path(), &["commit", "--quiet", "-m", "base"]);
    let main_branch = git_fixture(directory.path(), &["branch", "--show-current"]);

    git_fixture(directory.path(), &["checkout", "--quiet", "-b", "side"]);
    std::fs::write(directory.path().join("side.txt"), "side\n").unwrap();
    git_fixture(directory.path(), &["add", "side.txt"]);
    git_fixture(directory.path(), &["commit", "--quiet", "-m", "side"]);
    git_fixture(directory.path(), &["checkout", "--quiet", &main_branch]);
    std::fs::write(directory.path().join("main.txt"), "main\n").unwrap();
    git_fixture(directory.path(), &["add", "main.txt"]);
    git_fixture(directory.path(), &["commit", "--quiet", "-m", "main"]);
    git_fixture(
        directory.path(),
        &["merge", "--quiet", "--no-ff", "--no-commit", "side"],
    );
    std::fs::write(
        directory.path().join("schema.rs"),
        concat!(
            "attributes! {\n",
            "    \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" unsafe as merge_pin: ShortString;\n",
            "}\n",
        ),
    )
    .unwrap();
    git_fixture(directory.path(), &["add", "schema.rs"]);
    git_fixture(
        directory.path(),
        &["commit", "--quiet", "-m", "merge adds pin"],
    );

    let audit = collect_hits(directory.path(), &revs("HEAD^..HEAD"), &[]).unwrap();
    assert_eq!(
        audit.unsafe_attribute_hits.len(),
        1,
        "one semantic claim compared with two parents is one review occurrence"
    );
    assert!(audit.unsafe_attribute_hits[0]
        .evidence
        .starts_with("rust-attribute-added"));
}

#[test]
fn unsafe_attribute_findings_have_exact_decide_occurrences() {
    let directory = git_unsafe_attribute_fixture();
    let audit = collect_hits(directory.path(), &revs("HEAD^..HEAD"), &[]).unwrap();
    let hit = &audit.unsafe_attribute_hits[0];
    let occurrence = finding_id(modality::UNSAFE_ATTRIBUTE_ID, &hit.location);

    // Same declaration, rewritten commit: identity is the declaration's own
    // hash, so a rebase changes only the evidence.
    let rebased = GitHit {
        seen_in: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_owned(),
        display: "unsafe-attribute deadbeef:b/schema.rs:99  rewritten commit".to_owned(),
        ..hit.clone()
    };
    assert_eq!(
        occurrence,
        finding_id(modality::UNSAFE_ATTRIBUTE_ID, &rebased.location),
        "rewriting the introducing commit must not discard its declaration justification"
    );

    let Inner::Field(coordinate) = &hit.location.inner else {
        panic!("an unsafe-attribute claim is a named coordinate, not a byte range");
    };
    let changed = Location::field(
        hit.location.carrier.clone(),
        coordinate.replace("schema.rs", "other.rs"),
    );
    let changed_occurrence = finding_id(modality::UNSAFE_ATTRIBUTE_ID, &changed);
    assert_ne!(
        occurrence, changed_occurrence,
        "moving or changing the declaration is a new occurrence"
    );

    let store = TestStore::new();
    let decision = genid().id;
    let proposed = decide::decision_fragment(
        decision,
        "Justify this literal-pinned attribute identity",
        Some("It preserves rows written under this already-published byte id".to_owned()),
        Some(occurrence),
        point_interval(Epoch::from_unix_seconds(6_000.0)),
    )
    .unwrap()
    .0;
    store.publish_raw(DEFAULT_DECIDE_SCOPE_ID, proposed, "attribute justification");
    let resolved = decide::resolution_fragment(
        decision,
        "benign, and here is a whole sentence of reasoning about why",
        Some(decide::RESULT_BENIGN),
        true,
        &[],
        &[],
        point_interval(Epoch::from_unix_seconds(6_001.0)),
    )
    .unwrap()
    .0;
    store.publish_raw(
        DEFAULT_DECIDE_SCOPE_ID,
        resolved,
        "attribute classification",
    );
    let view = store.storage().decide_view().unwrap();
    let benign = settled_findings(&view.reader, &view.facts, BTreeMap::new()).unwrap();
    assert!(benign.justified.contains(&occurrence));
    assert!(!benign.justified.contains(&changed_occurrence));
}

#[test]
fn finding_lookup_treats_the_entity_id_as_opaque() {
    let location = Location::field(
        Carrier::GitBlob("0123456789abcdef0123456789abcdef01234567".to_owned()),
        "src/schema.rs#attribute",
    );
    let mut fragment = Fragment::empty();
    let carrier: TextHandle = fragment.put(location.carrier.address().to_owned());
    let locator: TextHandle = match &location.inner {
        Inner::Field(field) => fragment.put(field.clone()),
        Inner::Span { .. } => unreachable!(),
    };
    let extrinsic = Id::new([0xa7; 16]).unwrap();
    fragment += entity! { ExclusiveId::force_ref(&extrinsic) @
        metadata::tag: KIND_FINDING,
        metadata::tag: modality::UNSAFE_ATTRIBUTE_ID,
        posture::carrier_kind: location.carrier.kind(),
        posture::carrier: carrier,
        posture::locator: locator,
    };

    assert_eq!(
        findings_at(fragment.facts(), modality::UNSAFE_ATTRIBUTE_ID, &location,),
        BTreeSet::from([extrinsic]),
    );
}

#[test]
fn unsafe_attribute_clearance_requires_decide_proposal_context() {
    let store = TestStore::new();
    let occurrence = genid().id;

    let decision = genid().id;
    let proposal = decide::decision_fragment(
        decision,
        "Classify literal-pinned attribute",
        None,
        Some(occurrence),
        point_interval(Epoch::from_unix_seconds(6_100.0)),
    )
    .unwrap()
    .0;
    store.publish_raw(DEFAULT_DECIDE_SCOPE_ID, proposal, "unexplained proposal");
    let resolution = decide::resolution_fragment(
        decision,
        "benign, and here is a whole sentence of reasoning about why",
        Some(decide::RESULT_BENIGN),
        true,
        &[],
        &[],
        point_interval(Epoch::from_unix_seconds(6_101.0)),
    )
    .unwrap()
    .0;
    store.publish_raw(DEFAULT_DECIDE_SCOPE_ID, resolution, "unexplained benign");

    let view = store.storage().decide_view().unwrap();
    let benign = settled_findings(&view.reader, &view.facts, BTreeMap::new()).unwrap();
    assert!(benign.ordinary.contains(&occurrence));
    assert!(!benign.justified.contains(&occurrence));
    assert!(benign.hides(modality::PROTECTED_TERM, occurrence));
    assert!(!benign.hides(modality::UNSAFE_ATTRIBUTE_ID, occurrence));
    drop(view);

    let explained = genid().id;
    let proposal = decide::decision_fragment(
        explained,
        "Classify literal-pinned attribute",
        Some("This exact byte id and encoding preserve already-published rows".to_owned()),
        Some(occurrence),
        point_interval(Epoch::from_unix_seconds(6_102.0)),
    )
    .unwrap()
    .0;
    store.publish_raw(DEFAULT_DECIDE_SCOPE_ID, proposal, "explained proposal");
    let resolution = decide::resolution_fragment(
        explained,
        "benign, and here is a whole sentence of reasoning about why",
        Some(decide::RESULT_BENIGN),
        true,
        &[],
        &[],
        point_interval(Epoch::from_unix_seconds(6_103.0)),
    )
    .unwrap()
    .0;
    store.publish_raw(DEFAULT_DECIDE_SCOPE_ID, resolution, "explained benign");
    let view = store.storage().decide_view().unwrap();
    let benign = settled_findings(&view.reader, &view.facts, BTreeMap::new()).unwrap();
    assert!(benign.hides(modality::UNSAFE_ATTRIBUTE_ID, occurrence));
}

/// A resolution's PROSE is for a human. Only the result tag clears a
/// finding — except for the pre-tag resolutions, which had nothing else,
/// and are read exactly as they always were.
#[test]
fn only_a_result_tag_clears_a_finding_and_legacy_prose_still_does() {
    let store = TestStore::new();

    let cleared = |title: &'static str, outcome: &'static str, result: Option<Id>, at: f64| {
        let finding = genid().id;
        let decision = genid().id;
        store.publish_raw(
            DEFAULT_DECIDE_SCOPE_ID,
            decide::decision_fragment(
                decision,
                title,
                Some("justified".to_owned()),
                Some(finding),
                point_interval(Epoch::from_unix_seconds(at)),
            )
            .unwrap()
            .0,
            "clearance proposal",
        );
        store.publish_raw(
            DEFAULT_DECIDE_SCOPE_ID,
            decide::resolution_fragment(
                decision,
                outcome,
                result,
                true,
                &[],
                &[],
                point_interval(Epoch::from_unix_seconds(at + 1.0)),
            )
            .unwrap()
            .0,
            "clearance resolution",
        );
        let view = store.storage().decide_view().unwrap();
        let settled = settled_findings(&view.reader, &view.facts, BTreeMap::new()).unwrap();
        settled.hides(modality::PROTECTED_TERM, finding)
    };

    // The tag clears, and the prose is free to be an actual explanation.
    assert!(cleared(
        "tagged",
        "benign - it is a BPE vocabulary, so it spells most of the lexicon",
        Some(decide::RESULT_BENIGN),
        7_000.0
    ));
    // Pre-tag clearances carried the exact word and nothing else.
    assert!(cleared(
        "legacy prose",
        LEGACY_BENIGN_OUTCOME,
        None,
        7_100.0
    ));
    // Everything else is prose a program must not read as clearance.
    assert!(!cleared("near miss", "Benign.", None, 7_200.0));
    assert!(!cleared(
        "reasoned but untagged",
        "benign, because X",
        None,
        7_300.0
    ));
}

#[test]
fn identical_git_lines_are_distinct_exact_occurrences() {
    let directory = git_audit_fixture();
    let terms = vec![("project-sunrise".to_owned(), "fixture".to_owned())];
    let audit = collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap();
    let object_id = git_fixture(directory.path(), &["rev-parse", "HEAD"]);
    let term_hits = &audit.hits["project-sunrise"];

    let patch_hits = term_hits
        .iter()
        .filter(|hit| hit.evidence.starts_with("patch "))
        .collect::<Vec<_>>();
    assert_eq!(patch_hits.len(), 2);
    assert_ne!(patch_hits[0].location, patch_hits[1].location);
    assert!(patch_hits
        .iter()
        .all(|hit| hit.evidence.contains(&object_id)));
    assert_ne!(
        finding_id(modality::PROTECTED_TERM, &patch_hits[0].location),
        finding_id(modality::PROTECTED_TERM, &patch_hits[1].location)
    );

    let message_hits = term_hits
        .iter()
        .filter(|hit| hit.evidence.starts_with("message "))
        .collect::<Vec<_>>();
    assert_eq!(message_hits.len(), 2);
    assert_ne!(message_hits[0].location, message_hits[1].location);
}

#[test]
fn full_object_ids_not_display_prefixes_define_git_occurrences() {
    let first_object_id = format!("12345678{}", "0".repeat(32));
    let second_object_id = format!("12345678{}", "1".repeat(32));
    let first = git_hit(
        "patch",
        Location::span(Carrier::GitBlob(first_object_id.clone()), 0, 15),
        &first_object_id,
        "b/fixture.txt:1:diff-7",
        "+project-sunrise",
    );
    let second = git_hit(
        "patch",
        Location::span(Carrier::GitBlob(second_object_id.clone()), 0, 15),
        &second_object_id,
        "b/fixture.txt:1:diff-7",
        "+project-sunrise",
    );

    assert!(first.display.contains("12345678"));
    assert!(second.display.contains("12345678"));
    assert!(!first.display.contains(&first_object_id));
    assert!(!second.display.contains(&second_object_id));
    assert_ne!(first.location, second.location);

    assert_ne!(
        finding_id(modality::PROTECTED_TERM, &first.location),
        finding_id(modality::PROTECTED_TERM, &second.location)
    );
}

/// A repository whose HEAD carries a protected term on one line of one
/// file, with unrelated lines around it to move it against later.
fn git_carry_forward_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    git_fixture(directory.path(), &["init", "--quiet"]);
    std::fs::write(directory.path().join("base.txt"), "unrelated\n").unwrap();
    git_fixture(directory.path(), &["add", "base.txt"]);
    git_fixture(directory.path(), &["commit", "--quiet", "-m", "base"]);
    std::fs::write(
        directory.path().join("notes.md"),
        "intro\nproject-sunrise appears here\ntail\n",
    )
    .unwrap();
    git_fixture(directory.path(), &["add", "notes.md"]);
    git_fixture(directory.path(), &["commit", "--quiet", "-m", "add notes"]);
    directory
}

fn fixture_terms() -> Vec<(String, String)> {
    vec![("project-sunrise".to_owned(), "fixture".to_owned())]
}

/// Finding ids for one term, restricted to a kind of sighting ("patch",
/// "message", "path").
fn finding_ids(audit: &GitAudit, term: &str, kind: &str) -> BTreeSet<Id> {
    audit
        .hits
        .get(term)
        .into_iter()
        .flatten()
        .filter(|hit| hit.evidence.starts_with(&format!("{kind} ")))
        .map(|hit| finding_id(modality::PROTECTED_TERM, &hit.location))
        .collect()
}

/// THE property the redesign exists for. Commit surgery rewrites commits
/// and leaves blobs byte-identical, so the material keeps its id and every
/// Decide resolution about it keeps applying.
#[test]
fn commit_surgery_that_preserves_the_blob_preserves_the_finding_id() {
    let directory = git_carry_forward_fixture();
    let terms = fixture_terms();
    let before = collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap();
    let before_ids = finding_ids(&before, "project-sunrise", "patch");
    assert_eq!(before_ids.len(), 1, "one protected line, one finding");
    let head_before = git_fixture(directory.path(), &["rev-parse", "HEAD"]);
    let blob_before = git_fixture(directory.path(), &["rev-parse", "HEAD:notes.md"]);

    // Amend and then rebase the whole history: new commit ids throughout.
    git_fixture(
        directory.path(),
        &[
            "commit",
            "--amend",
            "--quiet",
            "--no-edit",
            "--date=2001-02-03T04:05:06",
        ],
    );
    git_fixture(
        directory.path(),
        &["rebase", "--quiet", "--force-rebase", "--root"],
    );
    let head_after = git_fixture(directory.path(), &["rev-parse", "HEAD"]);
    let blob_after = git_fixture(directory.path(), &["rev-parse", "HEAD:notes.md"]);
    assert_ne!(head_before, head_after, "the fixture must actually rewrite");
    assert_eq!(blob_before, blob_after, "a rebase does not touch blobs");

    let after = collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap();
    assert_eq!(
        before_ids,
        finding_ids(&after, "project-sunrise", "patch"),
        "the same material at a new commit is the same finding"
    );
    let commits = after.hits["project-sunrise"]
        .iter()
        .filter(|hit| hit.evidence.starts_with("patch "))
        .map(|hit| hit.seen_in.clone())
        .collect::<BTreeSet<_>>();
    assert!(
        !commits.contains(&head_before),
        "the locator cache follows the rewrite even though identity does not"
    );
}

/// git decides what moved. A line lifted into another file inside a commit
/// that also edits it is not new material, and `blame -M -C` is the thing
/// that knows so — which is why posture asks instead of matching for
/// itself.
#[test]
fn moved_material_is_carried_forward_and_new_material_is_not() {
    let directory = git_carry_forward_fixture();
    let terms = fixture_terms();
    let introduced = finding_ids(
        &collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap(),
        "project-sunrise",
        "patch",
    );
    assert_eq!(introduced.len(), 1);

    // Move the file AND change it, so the new path's blob is genuinely a
    // different object from the one the material was introduced in.
    git_fixture(directory.path(), &["mv", "notes.md", "docs.md"]);
    let moved = directory.path().join("docs.md");
    let body = std::fs::read_to_string(&moved).unwrap();
    std::fs::write(&moved, format!("{body}extra unrelated line\n")).unwrap();
    git_fixture(directory.path(), &["add", "-A"]);
    git_fixture(
        directory.path(),
        &["commit", "--quiet", "-m", "move and extend notes"],
    );
    assert_ne!(
        git_fixture(directory.path(), &["rev-parse", "HEAD:docs.md"]),
        git_fixture(directory.path(), &["rev-parse", "HEAD~1:notes.md"]),
        "the moved file must have a new blob for this test to mean anything"
    );

    let after_move = finding_ids(
        &collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap(),
        "project-sunrise",
        "patch",
    );
    assert_eq!(
        introduced, after_move,
        "material git reports as moved must not be re-created as a new finding"
    );

    // Negative control: a genuinely new instance of the same term, in
    // another file, is a DIFFERENT finding — every instance is judged, and
    // the equality above is not everything collapsing into one id.
    std::fs::write(
        directory.path().join("other.md"),
        "project-sunrise elsewhere\n",
    )
    .unwrap();
    git_fixture(directory.path(), &["add", "other.md"]);
    git_fixture(
        directory.path(),
        &["commit", "--quiet", "-m", "second instance"],
    );
    let after_new = finding_ids(
        &collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap(),
        "project-sunrise",
        "patch",
    );
    assert_eq!(
        after_new.len(),
        2,
        "the same string in a second place is a second judgement"
    );
    assert!(after_new.is_superset(&introduced));
}

/// The honest exception, asserted rather than assumed: a commit message has
/// no blob, so its carrier is the commit, and commit surgery DOES move it.
/// A reworded or rebased message re-blocks and needs a fresh decision.
#[test]
fn a_commit_message_finding_does_not_survive_commit_surgery() {
    let directory = tempfile::tempdir().unwrap();
    git_fixture(directory.path(), &["init", "--quiet"]);
    std::fs::write(directory.path().join("base.txt"), "unrelated\n").unwrap();
    git_fixture(directory.path(), &["add", "base.txt"]);
    git_fixture(
        directory.path(),
        &["commit", "--quiet", "-m", "mentions project-sunrise"],
    );
    let terms = fixture_terms();
    let before = finding_ids(
        &collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap(),
        "project-sunrise",
        "message",
    );
    assert_eq!(before.len(), 1);

    git_fixture(
        directory.path(),
        &[
            "commit",
            "--amend",
            "--quiet",
            "--no-edit",
            "--date=2001-02-03T04:05:06",
        ],
    );
    let after = finding_ids(
        &collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap(),
        "project-sunrise",
        "message",
    );
    assert_eq!(after.len(), 1);
    assert_ne!(
        before, after,
        "there is no content-addressed carrier for a message; say so plainly"
    );
}

#[test]
fn git_subprocess_errors_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let terms = vec![("project-sunrise".to_owned(), "fixture".to_owned())];
    let error = collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap_err();
    assert!(error.to_string().contains("git -C"));

    let error = git_probe(directory.path(), &["remote", "get-url", "origin"], &[2]).unwrap_err();
    assert!(error.to_string().contains("git -C"));
}
