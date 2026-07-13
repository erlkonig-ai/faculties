//! Faculty-level proof for the checkout-free archive BM25 search path.
//!
//! Builds a fresh temporary pile with a handful of synthetic archive
//! messages, then drives the REAL `archive` binary:
//!
//! 1. `archive list`, `archive show`, and `archive search` before `archive index` error rather
//!    than checking out the raw archive.
//! 2. `archive index` replays source commits into Succinct + BM25 LSM leaves.
//! 3. `archive list --limit N` returns the newest N messages from the
//!    Succinct union by k-way merging reverse `created_at` AVE cursors, with
//!    bounded selection work and no source checkout.
//! 4. `archive show <id>` resolves full and prefix IDs through the Succinct
//!    union, materializes only the selected message graph, and preserves the
//!    established output ordering.
//! 5. `archive search <term>` returns exactly the messages whose content
//!    contains `<term>`, BM25-ranked, with each hit's author + content
//!    snippet resolved through the cross-segment Succinct union and per-hit
//!    blob gets, with NO full `ws.checkout(..)` of the branch on the query
//!    path.
//! 6. Standalone and repeated Unicode symbols are regular indexed terms,
//!    not an accidental request for the archive-scale exact scan.
//!
//! The exact ranking equivalence to the old monolithic index is proven
//! at the crate level in
//! `triblespace_search::index_bm25::tests::single_segment_equals_monolithic_oracle`;
//! this test proves the faculty wiring end-to-end.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::SigningKey;
use hifitime::Epoch;
use rand_core::OsRng;

use faculties::schemas::archive::archive;
use triblespace::core::metadata;
use triblespace::core::repo::index_home::{
    seg_succinct_rank9, IndexHome, IndexKind, Manifest, SuccinctRollup,
};
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{PushResult, Repository};
use triblespace::prelude::blobencodings::{LongString, SimpleArchive};
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;
use triblespace_search::index_bm25::Bm25Rollup;

/// A fresh, unique temp pile path. Honours the job's temp dir when
/// `CLAUDE_JOB_TMP` is set; otherwise falls back to the system temp dir.
/// Never a real pile.
fn temp_pile_path() -> PathBuf {
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    let dir = std::env::var("CLAUDE_JOB_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    dir.join(format!(
        "faculties-archive-test-{}-{}-{}.pile",
        std::process::id(),
        nanos,
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ))
}

fn run_archive(pile: &PathBuf, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_archive"))
        .arg("--pile")
        .arg(pile)
        .arg("--branch")
        .arg("archive")
        .args(args)
        .output()
        .expect("run archive binary")
}

fn unique_prefix(target: Id, candidates: &[Id]) -> String {
    let full = format!("{target:x}");
    (1..32)
        .map(|len| full[..len].to_owned())
        .find(|prefix| {
            candidates
                .iter()
                .filter(|candidate| format!("{candidate:x}").starts_with(prefix))
                .count()
                == 1
        })
        .expect("a full ID is unique")
}

fn message_ids_with_an_ambiguous_prefix(count: usize) -> Vec<Id> {
    assert!(count >= 2);
    let first = *rngid();
    let first_hex = format!("{first:x}");
    let mut ids = vec![first];
    while ids.len() < count {
        let candidate = *rngid();
        if ids.contains(&candidate) {
            continue;
        }
        if ids.len() == 1 && !format!("{candidate:x}").starts_with(&first_hex[..1]) {
            continue;
        }
        ids.push(candidate);
    }
    ids
}

#[test]
fn bm25_fast_path_resolves_content_without_checkout() {
    let path = temp_pile_path();

    // ── build a fresh archive pile with synthetic messages ────────────────
    // Known vocabulary so we can assert which docs a query must return.
    let docs = [
        ("alpha beta gamma memory", "message A"),
        ("beta delta pile", "message B"),
        ("gamma delta epsilon trible", "message C"),
        ("telemetry symbol alpha 🛰️, status nominal", "message D"),
        (
            "telemetry symbol alpha cluster 🛰️🛰️🛰️ status stable",
            "message E",
        ),
        ("symbol beta 🧭", "message F"),
        ("symbol gamma 🔭", "message G"),
        ("symbol delta 🪐", "message H"),
    ];
    let msg_ids = message_ids_with_an_ambiguous_prefix(docs.len());
    let show_parent = *fucid();
    let show_attachments = [*fucid(), *fucid()];
    let non_message_with_message_fields = *fucid();
    let branch_id;
    {
        std::fs::File::create(&path).expect("create empty pile file");
        let pile = Pile::open(&path).expect("open temp pile");
        let mut repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
            .expect("create repo");
        branch_id = *repo.create_branch("archive", None).expect("branch");

        let mut ws = repo.pull(branch_id).expect("pull");
        let mut change = TribleSet::new();

        // One author.
        let author = *fucid();
        let author_name = ws.put::<LongString, _>("Tester".to_owned());
        let author_role = ws.put::<LongString, _>("user".to_owned());
        change += entity! { ExclusiveId::force_ref(&author) @
            metadata::tag: archive::kind_author,
            archive::author_name: author_name,
            archive::author_role: author_role,
        };

        // Messages, one second apart so timestamps are distinct.
        for (i, (id, (text, _label))) in msg_ids.iter().zip(&docs).enumerate() {
            let content = ws.put::<LongString, _>((*text).to_owned());
            let when = Epoch::from_gregorian_tai(2026, 1, 1, 0, 0, i as u8, 0);
            let created_at: Inline<inlineencodings::NsTAIInterval> =
                (when, when).try_to_inline().unwrap();
            change += entity! { ExclusiveId::force_ref(id) @
                metadata::tag: archive::kind_message,
                archive::author: author,
                archive::content: content,
                metadata::created_at: created_at,
            };
        }

        // Give the first message every optional field `show` renders. Two
        // attachments exercise deterministic ID ordering and the
        // name/source-id label fallback through the Succinct union.
        change += entity! { ExclusiveId::force_ref(&msg_ids[0]) @
            archive::reply_to: show_parent,
            archive::content_type: "text",
            archive::attachment: show_attachments[0],
        };
        change += entity! { ExclusiveId::force_ref(&msg_ids[0]) @
            archive::attachment: show_attachments[1],
        };
        let attachment_name = ws.put::<LongString, _>("diagram.png".to_owned());
        change += entity! { ExclusiveId::force_ref(&show_attachments[0]) @
            metadata::tag: archive::kind_attachment,
            archive::attachment_name: attachment_name,
            archive::attachment_mime: "image/png",
            archive::attachment_size_bytes: 123u64,
            archive::attachment_width_px: 20u64,
            archive::attachment_height_px: 10u64,
        };
        let attachment_source = ws.put::<LongString, _>("source-b".to_owned());
        change += entity! { ExclusiveId::force_ref(&show_attachments[1]) @
            metadata::tag: archive::kind_attachment,
            archive::attachment_source_id: attachment_source,
        };

        // A full 32-char ID bypasses prefix candidate enumeration. Keep an
        // entity with all required display fields but the wrong kind tag to
        // prove the materialization query itself still enforces message kind.
        let impostor_content = ws.put::<LongString, _>("not a message sentinel".to_owned());
        let impostor_when = Epoch::from_gregorian_tai(2026, 1, 1, 0, 2, 0, 0);
        let impostor_created_at: Inline<inlineencodings::NsTAIInterval> =
            (impostor_when, impostor_when).try_to_inline().unwrap();
        change += entity! { ExclusiveId::force_ref(&non_message_with_message_fields) @
            metadata::tag: archive::kind_author,
            archive::author: author,
            archive::content: impostor_content,
            metadata::created_at: impostor_created_at,
        };

        // A newer timestamped non-message must not consume the result limit.
        // The AVE cursor intentionally sees it first, then the bound union
        // query rejects it before selecting H and G.
        let timestamped_non_message = *fucid();
        let when = Epoch::from_gregorian_tai(2026, 1, 1, 0, 1, 0, 0);
        let created_at: Inline<inlineencodings::NsTAIInterval> =
            (when, when).try_to_inline().unwrap();
        change += entity! { ExclusiveId::force_ref(&timestamped_non_message) @
            metadata::tag: archive::kind_author,
            metadata::created_at: created_at,
        };

        ws.commit(change.clone(), "stage synthetic archive");
        repo.push(&mut ws).expect("push");

        repo.close().expect("close");
    }

    // ── 1. indexed reads before index: clean errors, never raw fallback ───
    let out = run_archive(&path, &["list", "--limit", "1"]);
    assert!(
        !out.status.success(),
        "list before index must fail instead of checking out raw history; stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Succinct index")
            && stderr.contains("stale")
            && stderr.contains("archive index"),
        "expected stale Succinct coverage hint, got: {stderr}"
    );

    let first_message_id = format!("{:x}", msg_ids[0]);
    let out = run_archive(&path, &["show", first_message_id.as_str()]);
    assert!(
        !out.status.success(),
        "show before index must fail instead of checking out raw history; stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Succinct index") && stderr.contains("stale"),
        "expected stale Succinct coverage hint for show, got: {stderr}"
    );

    let out = run_archive(&path, &["search", "beta"]);
    assert!(
        !out.status.success(),
        "search before index should fail; stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("BM25 index") && stderr.contains("stale"),
        "expected stale BM25 coverage hint, got: {stderr}"
    );

    // ── 2. index: replay the source commit into both LSMs ─────────────────
    let out = run_archive(&path, &["index"]);
    assert!(
        out.status.success(),
        "index failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Succinct and BM25 typed indexes now cover HEAD"),
        "index summary: {stdout}"
    );

    // Show resolves both a full ID and a unique prefix through the certified
    // Succinct union. Rendering order remains byte-for-byte compatible with
    // the former raw-checkout path, including deterministic attachments.
    let mut attachment_lines = [
        (
            show_attachments[0],
            format!(
                "  - {} diagram.png (image/png, 123b, 20x10px)",
                &format!("{:x}", show_attachments[0])[..8]
            ),
        ),
        (
            show_attachments[1],
            format!(
                "  - {} source-b",
                &format!("{:x}", show_attachments[1])[..8]
            ),
        ),
    ];
    attachment_lines.sort_by_key(|(id, _)| *id);
    let show_when = Epoch::from_gregorian_tai(2026, 1, 1, 0, 0, 0, 0);
    let expected_show = format!(
        "id: {:x}\ncreated_at: {}\nauthor: Tester (user)\nreply_to: {:x}\ncontent_type: text\nattachments: 2\n{}\n{}\n\n{}\n",
        msg_ids[0],
        show_when,
        show_parent,
        attachment_lines[0].1,
        attachment_lines[1].1,
        docs[0].0,
    );
    let out = run_archive(&path, &["show", first_message_id.as_str()]);
    assert!(
        out.status.success(),
        "full-ID show failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), expected_show);

    let first_message_prefix = unique_prefix(msg_ids[0], &msg_ids);
    let out = run_archive(&path, &["show", first_message_prefix.as_str()]);
    assert!(
        out.status.success(),
        "prefix show failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), expected_show);

    let first_hex = format!("{:x}", msg_ids[0]);
    let ambiguous_prefix = (1..32)
        .rev()
        .map(|len| first_hex[..len].to_owned())
        .find(|prefix| {
            msg_ids
                .iter()
                .filter(|id| format!("{id:x}").starts_with(prefix))
                .count()
                > 1
        })
        .expect("fixture IDs deliberately share a prefix");
    let out = run_archive(&path, &["show", ambiguous_prefix.as_str()]);
    assert!(
        !out.status.success(),
        "ambiguous prefix must not pick a row"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("matches for prefix"),
        "ambiguous-prefix diagnostic: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let impostor_id = format!("{non_message_with_message_fields:x}");
    let out = run_archive(&path, &["show", impostor_id.as_str()]);
    assert!(
        !out.status.success(),
        "a non-message with display-like fields must not masquerade as a message"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("missing required fields"),
        "wrong-kind diagnostic: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = run_archive(&path, &["--trace", "show", first_message_prefix.as_str()]);
    assert!(
        out.status.success(),
        "traced show failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.matches("pile record refresh complete").count(),
        1,
        "show must open/refresh its pile once; trace:\n{stdout}"
    );
    assert!(
        stdout.contains("indexed-read branch resolution complete")
            && !stdout.contains("command branch resolution complete"),
        "show must use indexed standalone dispatch, never raw checkout dispatch; trace:\n{stdout}"
    );

    // List attaches the certified Succinct snapshot, keeps only the newest
    // two records, then fetches blobs for those winners. Fixture timestamps
    // increase with the document ordinal, so H and G win and F is excluded.
    let out = run_archive(&path, &["list", "--limit", "2"]);
    assert!(
        out.status.success(),
        "indexed list failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("symbol delta 🪐") && stdout.contains("symbol gamma 🔭"),
        "list must return the two newest messages; got:\n{stdout}"
    );
    assert!(
        !stdout.contains("symbol beta 🧭"),
        "list limit must exclude the third-newest message; got:\n{stdout}"
    );

    let out = run_archive(&path, &["list", "--limit", "0"]);
    assert!(
        out.status.success() && out.stdout.is_empty(),
        "zero-limit list must validate the index but emit nothing; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Total per-artifact documents equal the source corpus exactly once.
    {
        let mut pile = Pile::open(&path).expect("open pile");
        pile.refresh().expect("refresh pile");
        let mut repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
            .expect("open indexed repo");
        let source_head = repo.pull(branch_id).expect("pull indexed branch").head();
        let reader = repo.storage_mut().reader().expect("indexed BM25 reader");
        let kind = Bm25Rollup::new(reader, archive::content.id());
        let mut home = IndexHome::new(repo.storage_mut(), branch_id, kind);
        let manifest = home.read_manifest().expect("read indexed manifest");
        assert!(manifest.claims_head(source_head));
        let segments = home
            .attach_manifest(&manifest)
            .expect("attach indexed artifacts");
        assert_eq!(
            segments
                .iter()
                .map(|segment| segment.doc_count())
                .sum::<usize>(),
            docs.len() + 1,
            "typed ranges must not duplicate source postings"
        );
        repo.close().expect("close indexed repo");
    }

    // ── 3. search "beta": must return A and B (contain 'beta'), not C ─────
    // Discriminate by the RESOLVED content snippet (the binary prints
    // only 8 hex of the id, which `fucid` shares as a timestamp prefix
    // across ids minted together). Matching content is the stronger
    // proof anyway: it shows the text was resolved via the Succinct union + a
    // blob get, with no branch checkout. A's unique token is "alpha",
    // B's is "pile", C's is "epsilon".
    let out = run_archive(&path, &["search", "beta"]);
    assert!(
        out.status.success(),
        "search failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("alpha"),
        "'beta' must return message A; got:\n{stdout}"
    );
    assert!(
        stdout.contains("pile"),
        "'beta' must return message B; got:\n{stdout}"
    );
    assert!(
        !stdout.contains("epsilon"),
        "'beta' must NOT return message C; got:\n{stdout}"
    );
    // Author name resolved from the Succinct union too.
    assert!(
        stdout.contains("Tester"),
        "author name resolved; got:\n{stdout}"
    );

    // A search process refreshes the pile record index exactly once. The
    // trace assertion is structural rather than timing-based, so it remains
    // stable on slow CI hosts. A zero-result-limit query also has no reason
    // to materialize any source checkout.
    let out = run_archive(&path, &["--trace", "search", "--limit", "0", "beta"]);
    assert!(
        out.status.success(),
        "traced search failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.matches("pile record refresh complete").count(),
        1,
        "search must open/refresh its pile once; trace:\n{stdout}"
    );
    assert!(
        !stdout.contains("content rollup"),
        "search no longer uses the legacy monolithic rollup; trace:\n{stdout}"
    );
    assert!(
        !stdout.contains("Succinct manifest and segments attached"),
        "a zero-limit query must not attach the Succinct LSM; trace:\n{stdout}"
    );

    // ── 4. a rare term hits exactly its one document ──────────────────────
    let out = run_archive(&path, &["search", "epsilon"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("epsilon") && !stdout.contains("alpha"),
        "'epsilon' must return only message C; got:\n{stdout}"
    );

    // ── 5. absent term returns nothing ────────────────────────────────────
    let out = run_archive(&path, &["search", "zzzabsentzzz"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    for token in ["alpha", "pile", "epsilon"] {
        assert!(
            !stdout.contains(token),
            "absent term must return no messages; got:\n{stdout}"
        );
    }

    // A standalone Unicode symbol uses the BM25 fast path. The synthetic
    // fixtures cover punctuation adjacency and a repeated symbol cluster.
    let out = run_archive(&path, &["search", "🛰️"]);
    assert!(
        out.status.success(),
        "symbol search failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("status nominal"),
        "punctuation-adjacent symbol must match; got:\n{stdout}"
    );
    assert!(
        stdout.contains("status stable"),
        "a symbol inside a repeated cluster must match; got:\n{stdout}"
    );
    assert!(
        !stdout.contains("symbol beta"),
        "a different symbol must not match; got:\n{stdout}"
    );

    // Similar Unicode symbols receive distinct, context-free terms too.
    let out = run_archive(&path, &["search", "🧭"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("symbol beta") && !stdout.contains("symbol gamma"),
        "the first generic symbol must resolve independently; got:\n{stdout}"
    );
    let out = run_archive(&path, &["search", "🔭"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("symbol gamma") && !stdout.contains("symbol beta"),
        "the second generic symbol must resolve independently; got:\n{stdout}"
    );
    let out = run_archive(&path, &["search", "🪐"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("symbol delta") && !stdout.contains("symbol beta"),
        "a newer emoji scalar must be indexed too; got:\n{stdout}"
    );

    // A real importer write goes through open_repo_for_write's combined
    // commit hook. Both its raw-tree commit and semantic commit must advance
    // Succinct+BM25 coverage, so the new token is searchable immediately —
    // no explicit `archive index` repair between import and query.
    let fixture = path.with_extension("conversations.json");
    std::fs::write(
        &fixture,
        r#"[{
          "id": "hook-conversation",
          "title": "hook coverage",
          "create_time": 1767225660.0,
          "mapping": {
            "hook-node": {
              "id": "hook-node",
              "parent": null,
              "children": [],
              "message": {
                "id": "hook-message",
                "author": {"role": "user", "name": "Hook Tester"},
                "create_time": 1767225660.0,
                "content": {"content_type": "text", "parts": ["livehookbeacon"]}
              }
            }
          }
        }]"#,
    )
    .expect("write ChatGPT fixture");
    let fixture_arg = fixture.to_string_lossy().into_owned();
    let out = run_archive(&path, &["import", "chatgpt", &fixture_arg]);
    assert!(
        out.status.success(),
        "hooked import failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run_archive(&path, &["search", "livehookbeacon"]);
    assert!(
        out.status.success(),
        "hook-maintained search failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("livehookbeacon"),
        "hook-maintained message must be searchable immediately"
    );

    // A writer that bypasses the process-local hook leaves the coverage
    // certificate behind. Even when the stale BM25 segments return no hits,
    // search must report the gap rather than silently accept an empty answer.
    {
        let mut pile = Pile::open(&path).expect("reopen temp pile");
        pile.refresh().expect("refresh temp pile");
        let mut repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
            .expect("reopen repo");
        let mut ws = repo.pull(branch_id).expect("pull archive branch");
        let author = *fucid();
        let author_name = ws.put::<LongString, _>("Later Tester".to_owned());
        let content = ws.put::<LongString, _>("postindexbeacon".to_owned());
        let message = *fucid();
        let when = Epoch::from_gregorian_tai(2026, 1, 1, 0, 1, 0, 0);
        let created_at: Inline<inlineencodings::NsTAIInterval> =
            (when, when).try_to_inline().unwrap();
        let mut change = TribleSet::new();
        change += entity! { ExclusiveId::force_ref(&author) @
            metadata::tag: archive::kind_author,
            archive::author_name: author_name,
        };
        change += entity! { ExclusiveId::force_ref(&message) @
            metadata::tag: archive::kind_message,
            archive::author: author,
            archive::content: content,
            metadata::created_at: created_at,
        };
        ws.commit(change, "append synthetic post-index message");
        repo.push(&mut ws).expect("push post-index message");
        repo.close().expect("close repo");
    }
    let out = run_archive(&path, &["search", "postindexbeacon"]);
    assert!(
        !out.status.success(),
        "stale index must not silently return an empty result"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("BM25 index") && stderr.contains("stale"),
        "stale-index diagnostic missing; stderr={stderr}"
    );
    let out = run_archive(&path, &["list", "--limit", "1"]);
    assert!(
        !out.status.success(),
        "stale list must fail instead of returning old indexed or new raw data"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Succinct index") && stderr.contains("stale"),
        "stale-list diagnostic missing; stderr={stderr}"
    );
    let out = run_archive(&path, &["show", first_message_id.as_str()]);
    assert!(
        !out.status.success(),
        "stale show must fail instead of returning old indexed or new raw data"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Succinct index") && stderr.contains("stale"),
        "stale-show diagnostic missing; stderr={stderr}"
    );

    // Repair walks only the uncovered commit, then the new message is
    // searchable through the two-segment unions.
    let out = run_archive(&path, &["index"]);
    assert!(
        out.status.success(),
        "incremental repair failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run_archive(&path, &["search", "postindexbeacon"]);
    assert!(
        out.status.success(),
        "search after repair failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("postindexbeacon"),
        "repaired commit must be searchable"
    );
    let out = run_archive(&path, &["list", "--limit", "2"]);
    assert!(
        out.status.success(),
        "list after repair failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("postindexbeacon"),
        "repaired recent message must be listable through the Succinct union"
    );

    // A completed rerun is a true no-op: it appends no duplicate corpus and
    // does not even repoint the branch metadata handle.
    let head_before = {
        let mut pile = Pile::open(&path).expect("open for head snapshot");
        pile.refresh().expect("refresh for head snapshot");
        let head = pile.head(branch_id).expect("read branch head");
        pile.close().expect("close head snapshot pile");
        head
    };
    let out = run_archive(&path, &["index"]);
    assert!(out.status.success(), "idempotent index rerun failed");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("already cover HEAD"),
        "expected no-op summary"
    );
    let head_after = {
        let mut pile = Pile::open(&path).expect("open for second head snapshot");
        pile.refresh().expect("refresh for second head snapshot");
        let head = pile.head(branch_id).expect("read second branch head");
        pile.close().expect("close second head snapshot pile");
        head
    };
    assert_eq!(head_before, head_after, "completed rebuild is idempotent");

    // Rank9 handles are repeated unordered typed facts, paired to raw
    // Succinct artifacts by the source handle embedded in each Rank9 blob.
    // Cross-wire one pair: repair must strip and rebuild only Succinct while
    // retaining the independently valid BM25 recipe byte-for-byte.
    let bm25_before_corruption;
    {
        let mut pile = Pile::open(&path).expect("open for corrupt-manifest setup");
        pile.refresh().expect("refresh corrupt-manifest setup");
        let mut repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
            .expect("open corrupt-manifest repo");
        let old_head = repo
            .storage_mut()
            .head(branch_id)
            .expect("read branch head");
        let branch_reader = repo.storage_mut().reader().expect("branch reader");
        let mut head_set: TribleSet = branch_reader
            .get(old_head.expect("branch metadata"))
            .expect("load branch metadata");
        let source_head = repo.pull(branch_id).expect("pull source").head();
        let reader = repo.storage_mut().reader().expect("typed manifest reader");
        let bm25_kind = Bm25Rollup::new(reader.clone(), archive::content.id());
        let bm25_manifest =
            Manifest::from_tribles(&head_set, &reader, &bm25_kind).expect("valid BM25 manifest");
        assert!(bm25_manifest.claims_head(source_head));
        bm25_before_corruption = bm25_manifest.to_tribles();
        let succinct_kind = SuccinctRollup::new();
        let succinct_manifest = Manifest::from_tribles(&head_set, &reader, &succinct_kind)
            .expect("valid Succinct manifest");
        assert!(succinct_manifest.claims_head(source_head));
        let target_range = succinct_manifest
            .ranges()
            .iter()
            .find(|range| !range.artifacts().is_empty())
            .expect("fixture has a Succinct artifact")
            .entity();
        let foreign_entity = *fucid();
        let foreign_source: TribleSet = entity! { ExclusiveId::force_ref(&foreign_entity) @
            metadata::tag: archive::kind_author,
        }
        .into();
        let foreign_prepared = succinct_kind
            .build(&foreign_source)
            .expect("build foreign Succinct artifact")
            .pop()
            .expect("nonempty foreign Succinct artifact");
        let foreign_rank9 = succinct_kind
            .put(repo.storage_mut(), foreign_prepared)
            .expect("store foreign Succinct artifact")
            .rank9();
        let mut old_rank9_fact = TribleSet::new();
        for fact in head_set
            .iter()
            .filter(|fact| *fact.e() == target_range && *fact.a() == seg_succinct_rank9.id())
        {
            old_rank9_fact.insert(fact);
        }
        assert_eq!(old_rank9_fact.len(), 1);
        head_set = head_set.difference(&old_rank9_fact);
        head_set += entity! { ExclusiveId::force_ref(&target_range) @
            seg_succinct_rank9: foreign_rank9,
        };

        let new_head: Inline<Handle<SimpleArchive>> = repo
            .storage_mut()
            .put(head_set)
            .expect("store corrupt manifest");
        assert!(matches!(
            repo.storage_mut()
                .update(branch_id, old_head, Some(new_head))
                .expect("publish corrupt manifest"),
            PushResult::Success()
        ));
        repo.close().expect("close corrupt-manifest repo");
    }
    let out = run_archive(&path, &["list", "--limit", "1"]);
    assert!(
        !out.status.success(),
        "list must not fall back when typed Succinct pairing is invalid"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("foreign raw archive"),
        "source-pairing list diagnostic: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run_archive(&path, &["show", first_message_id.as_str()]);
    assert!(
        !out.status.success(),
        "show must not fall back when typed Succinct pairing is invalid"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("foreign raw archive"),
        "source-pairing show diagnostic: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = run_archive(&path, &["index"]);
    assert!(
        out.status.success(),
        "repair of invalid Succinct source pairing failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("discarding only the invalid Succinct recipe"),
        "repair should diagnose only the invalid recipe: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    {
        let mut pile = Pile::open(&path).expect("open repaired manifest");
        pile.refresh().expect("refresh repaired manifest");
        let head = pile.head(branch_id).unwrap().unwrap();
        let reader = pile.reader().expect("repaired manifest reader");
        let head_set: TribleSet = reader.get(head).unwrap();
        let bm25_kind = Bm25Rollup::new(reader.clone(), archive::content.id());
        let bm25_after = Manifest::from_tribles(&head_set, &reader, &bm25_kind)
            .expect("BM25 survives Succinct repair");
        assert_eq!(bm25_after.to_tribles(), bm25_before_corruption);
        drop(reader);
        pile.close().unwrap();
    }
    let out = run_archive(&path, &["search", "beta"]);
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("alpha"),
        "rebuilt index must be searchable"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&fixture);
    // Best-effort: the replay-index sibling file is not created here, but
    // clean up any pile side-files defensively.
    let _ = std::fs::remove_file(path.with_extension("pile.replay-index.jsonl"));
}

#[test]
fn index_does_not_certify_unreadable_archive_content() {
    let path = temp_pile_path();
    let branch_id;
    let source_head;
    {
        std::fs::File::create(&path).expect("create empty pile file");
        let pile = Pile::open(&path).expect("open temp pile");
        let mut repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
            .expect("create repo");
        branch_id = *repo.create_branch("archive", None).expect("branch");

        let mut ws = repo.pull(branch_id).expect("pull");
        let author = *fucid();
        let message = *fucid();
        let missing = Inline::<Handle<LongString>>::new([0xD3; 32]);
        let when = Epoch::from_gregorian_tai(2026, 1, 2, 0, 0, 0, 0);
        let created_at: Inline<inlineencodings::NsTAIInterval> =
            (when, when).try_to_inline().unwrap();
        let mut change = TribleSet::new();
        change += entity! { ExclusiveId::force_ref(&message) @
            metadata::tag: archive::kind_message,
            archive::author: author,
            archive::content: missing,
            metadata::created_at: created_at,
        };
        ws.commit(change, "message with unavailable content");
        source_head = ws.head();
        repo.push(&mut ws).expect("push malformed source commit");
        repo.close().expect("close source pile");
    }

    let out = run_archive(&path, &["index"]);
    assert!(
        !out.status.success(),
        "indexing unavailable content must fail instead of certifying it"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unreadable"),
        "missing-content diagnostic: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut pile = Pile::open(&path).expect("reopen failed-index pile");
    pile.refresh().expect("refresh failed-index pile");
    let mut repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
        .expect("reopen repo");
    let reader = repo.storage_mut().reader().expect("BM25 reader");
    let bm25 = Bm25Rollup::new(reader, archive::content.id());
    let mut bm25_home = IndexHome::new(repo.storage_mut(), branch_id, bm25);
    let bm25_manifest = bm25_home.read_manifest().expect("BM25 manifest");
    assert!(bm25_manifest.ranges().is_empty());
    assert!(!bm25_manifest.claims_head(source_head));

    let mut succinct_home = IndexHome::new(repo.storage_mut(), branch_id, SuccinctRollup::new());
    let succinct_manifest = succinct_home.read_manifest().expect("Succinct manifest");
    assert!(succinct_manifest.ranges().is_empty());
    assert!(!succinct_manifest.claims_head(source_head));
    repo.close().expect("close failed-index pile");
    let _ = std::fs::remove_file(&path);
}
