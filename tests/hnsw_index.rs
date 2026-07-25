//! Faculty-level proof for the persisted HNSW index-home path.
//!
//! Stages synthetic 768-d embeddings DIRECTLY under entity ids on a fresh
//! temporary pile (no nomic model), refreshes the HNSW ranges via
//! [`embeddings::refresh_index`], then queries via
//! [`embeddings::nearest_via_index`] — the same fast path `memory similar` /
//! `wiki similar` now take. Proves the query attaches the persisted segment(s)
//! and returns the staged nearest neighbour WITHOUT a full checkout + rebuild.

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use faculties::schemas::embeddings::{self, Embedding768, DIM};
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{PinStore, Repository};
use triblespace::prelude::*;

/// A fresh, unique temp pile path. Honours the job's temp dir when
/// `CLAUDE_JOB_TMP` is set; otherwise falls back to the system temp dir.
/// Never a real pile.
fn temp_pile_path() -> PathBuf {
    let dir = std::env::var("CLAUDE_JOB_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    dir.join(format!(
        "faculties-hnsw-test-{}-{}.pile",
        std::process::id(),
        nanos
    ))
}

/// Deterministic pseudo-random L2-normalized vector, tagged by `seed`.
fn unit_vec(seed: u64) -> Vec<f32> {
    let mut rng = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
    let mut next = || {
        rng = rng.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        (z ^ (z >> 31)) as i64 as f32 / i64::MAX as f32
    };
    let mut v: Vec<f32> = (0..DIM).map(|_| next()).collect();
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if n > 0.0 {
        for x in &mut v {
            *x /= n;
        }
    }
    v
}

#[test]
fn similar_via_persisted_index_returns_staged_nearest() {
    let path = temp_pile_path();

    // ── build a fresh pile with staged embeddings ──────────────────────────
    let branch_id;
    let source_head;
    let ids: Vec<Id> = (0..24).map(|_| *fucid()).collect();
    let vecs: Vec<Vec<f32>> = (0..ids.len() as u64).map(unit_vec).collect();
    {
        std::fs::File::create(&path).expect("create empty pile file");
        let pile = Pile::open(&path).expect("open temp pile");
        let mut repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
            .expect("create repo");
        branch_id = *repo.create_branch("main", None).expect("branch");

        // A branch can have a truthful, current HNSW recipe before it has any
        // embeddings. The artifact-free range is a positive empty result, not
        // the stale/missing signal used to trigger a rebuild fallback.
        let mut ws = repo.pull(branch_id).expect("pull empty source");
        ws.commit(TribleSet::new(), "contentless initial commit");
        repo.push(&mut ws).expect("push contentless initial commit");
        let empty_head = ws.head();
        embeddings::refresh_index(&mut repo, branch_id).expect("certify empty HNSW index");
        let empty =
            embeddings::nearest_via_index(repo.storage_mut(), branch_id, empty_head, &vecs[0], 0.0)
                .expect("query certified empty index")
                .expect("current empty index is present");
        assert!(empty.is_empty());

        let mut ws = repo.pull(branch_id).expect("pull");
        let mut change = TribleSet::new();
        for (id, v) in ids.iter().zip(&vecs) {
            let handle = ws.put::<Embedding768, _>(v.clone());
            change += entity! { ExclusiveId::force_ref(id) @ embeddings::attr::embedding: handle };
        }
        ws.commit(change, "stage synthetic embeddings");
        repo.push(&mut ws).expect("push");
        source_head = ws.head();

        // Refresh the persisted HNSW ranges — the maintenance step `memory
        // embed` / `wiki embed` now run.
        embeddings::refresh_index(&mut repo, branch_id).expect("refresh hnsw index");
        repo.close().expect("close");
    }

    // ── reopen and query via the persisted segment (no rebuild) ────────────
    {
        let pile = Pile::open(&path).expect("reopen temp pile");
        let mut repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
            .expect("reopen repo");

        // Probe with entity 7's own vector: its own handle must rank first.
        let probe_idx = 7usize;
        let rows = embeddings::nearest_via_index(
            repo.storage_mut(),
            branch_id,
            source_head,
            &vecs[probe_idx],
            0.0,
        )
        .expect("query")
        .expect("a persisted HNSW artifact exists");
        assert!(!rows.is_empty(), "segment query returned candidates");

        // Map the top handle back to its entity via the staged tribles.
        let mut ws = repo.pull(branch_id).expect("pull");
        let space = ws.checkout(..).expect("checkout");
        let mut by_handle: std::collections::HashMap<[u8; 32], Id> =
            std::collections::HashMap::new();
        for (id, v) in ids.iter().zip(&vecs) {
            let h: Inline<inlineencodings::Handle<Embedding768>> = find!(
                h: Inline<inlineencodings::Handle<Embedding768>>,
                pattern!(&space, [{ *id @ embeddings::attr::embedding: ?h }])
            )
            .next()
            .unwrap_or_else(|| panic!("embedding trible for {id:x} present"));
            let _ = v;
            by_handle.insert(h.raw, *id);
        }

        let (top_cos, top_raw) = rows[0];
        let top_id = by_handle
            .get(&top_raw)
            .copied()
            .expect("top handle maps to a staged entity");
        assert_eq!(top_id, ids[probe_idx], "self is the nearest neighbour");
        assert!(top_cos > 0.99, "self-cosine ~1.0, got {top_cos}");

        drop((space, ws));

        // Advance the source branch without refreshing the derived recipe.
        // Both a caller pinned to the new checkout and one holding the old
        // checkout must receive the truthful fallback signal.
        let mut ws = repo.pull(branch_id).expect("pull for contentless commit");
        ws.commit(TribleSet::new(), "contentless source commit");
        repo.push(&mut ws).expect("push contentless source commit");
        let advanced_head = ws.head();
        assert!(embeddings::nearest_via_index(
            repo.storage_mut(),
            branch_id,
            advanced_head,
            &vecs[probe_idx],
            0.0,
        )
        .expect("stale query")
        .is_none());
        assert!(embeddings::nearest_via_index(
            repo.storage_mut(),
            branch_id,
            source_head,
            &vecs[probe_idx],
            0.0,
        )
        .expect("raced-old-checkout query")
        .is_none());

        // Resume from the first recipe frontier. The second source commit
        // has no embeddings, but still becomes a real empty range so the
        // manifest can exactly certify the advanced HEAD.
        embeddings::refresh_index(&mut repo, branch_id).expect("resume HNSW refresh");
        let resumed = embeddings::nearest_via_index(
            repo.storage_mut(),
            branch_id,
            advanced_head,
            &vecs[probe_idx],
            0.0,
        )
        .expect("query resumed index")
        .expect("resumed HNSW artifact exists");
        assert_eq!(resumed[0].1, top_raw);

        let reader = repo.storage_mut().reader().expect("typed HNSW reader");
        let rollup = embeddings::embedding_rollup(reader.clone());
        let manifest = {
            let mut home = triblespace::core::repo::index_home::IndexHome::new(
                repo.storage_mut(),
                branch_id,
                rollup,
            );
            home.read_manifest().expect("typed HNSW manifest")
        };
        assert!(manifest.claims_head(advanced_head));
        assert_eq!(manifest.ranges().len(), 3);
        assert_eq!(
            manifest
                .ranges()
                .iter()
                .filter(|range| range.artifacts().is_empty())
                .count(),
            2
        );
        manifest
            .audit_exact_cover(&reader)
            .expect("exact HNSW cover");
        drop(reader);

        // A completed refresh is a true no-op: neither the branch pin nor the
        // append-only pile length changes.
        let pin_before = repo.storage_mut().head(branch_id).unwrap();
        let len_before = std::fs::metadata(&path).unwrap().len();
        embeddings::refresh_index(&mut repo, branch_id).expect("idempotent HNSW refresh");
        assert_eq!(repo.storage_mut().head(branch_id).unwrap(), pin_before);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), len_before);

        repo.close().expect("close");
    }

    let _ = std::fs::remove_file(&path);
}
