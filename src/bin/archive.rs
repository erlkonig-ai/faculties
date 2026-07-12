
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use hifitime::Epoch;
use itertools::Itertools;
use tracing::info_span;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use triblespace::core::repo::index_home::{
    clear_manifest, set_coverage, IndexHome, IndexKind, Manifest, SuccinctRollup,
};
use triblespace::core::repo::{
    ancestors, commits_topological, difference, CommitSelector, PushResult,
};
use triblespace::prelude::blobencodings::{LongString, SimpleArchive};
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval, U256BE};
use triblespace::prelude::*;
use triblespace_search::index_bm25::{query_across, Bm25Rollup};
use triblespace_search::tokens::hash_tokens;

#[path = "importers/archive_import_chatgpt.rs"]
mod archive_import_chatgpt;
#[path = "importers/archive_import_codex.rs"]
mod archive_import_codex;
#[path = "importers/archive_import_copilot.rs"]
mod archive_import_copilot;
#[path = "importers/archive_import_gemini.rs"]
mod archive_import_gemini;
#[path = "importers/archive_import_claude_code.rs"]
mod archive_import_claude_code;
#[path = "importers/archive_import_claude_web.rs"]
mod archive_import_claude_web;
#[path = "importers/archive_import_agy.rs"]
mod archive_import_agy;
mod common {
    #![allow(dead_code)]

    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result, anyhow, bail};
    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use itertools::Itertools;
    use rand_core::OsRng;
    use rayon::ThreadPoolBuilder;
    use rayon::prelude::*;
    
    use tracing::info_span;
    use triblespace::core::blob::Blob;
    use triblespace::core::id::ExclusiveId;
    pub use triblespace::core::metadata;
    use triblespace::core::repo::index_home::{
        append_segment, set_coverage, IndexKind, Manifest,
    };
    use triblespace::core::repo::pile::Pile;
    use triblespace::core::repo::CommitBatch;
    use triblespace::core::repo::{Repository, Workspace};
    use triblespace::prelude::blobencodings::{LongString, SimpleArchive};
    use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval};
    use triblespace::prelude::*;
    use triblespace_search::index_bm25::Bm25Rollup;

    #[cfg(feature = "gpu-succinct")]
    use triblespace::core::repo::index_home::AcceleratedSuccinctRollup;
    #[cfg(not(feature = "gpu-succinct"))]
    use triblespace::core::repo::index_home::SuccinctRollup;
    #[cfg(feature = "gpu-succinct")]
    use triblespace_gpu::WgpuWaveletFreeze;

    pub use faculties::schemas::archive::{self as archive_schema, archive, import_schema};
    pub use faculties::schemas::memory::comb;

    pub type Repo = Repository<Pile>;
    pub type Ws = Workspace<Pile>;
    pub type CommitHandle = Inline<Handle<SimpleArchive>>;

    /// Bound the transient six-PATCH view used while freezing one physical
    /// SuccinctArchive leaf. A larger source commit is still one *logical*
    /// commit leaf; all of its physical shards land atomically before its
    /// coverage certificate advances.
    const INDEX_PHYSICAL_LEAF_TRIBLES: usize = 1 << 16;

    /// Conservative Apple Metal crossover measured against the summed input
    /// rows before cross-segment deduplication.
    #[cfg(feature = "gpu-succinct")]
    const GPU_SUCCINCT_MIN_INPUT_ROWS: usize = 300_000;

    #[cfg(feature = "gpu-succinct")]
    pub(super) type ArchiveSuccinctRollup = AcceleratedSuccinctRollup<WgpuWaveletFreeze>;

    #[cfg(not(feature = "gpu-succinct"))]
    pub(super) type ArchiveSuccinctRollup = SuccinctRollup;

    /// Construct one rollup per archive-indexing lifecycle. The hook keeps
    /// this value alive across push attempts and batches so the WGPU runtime,
    /// shader cache, allocator, and circuit-breaker state are reused.
    #[cfg(feature = "gpu-succinct")]
    pub(super) fn archive_succinct_rollup() -> ArchiveSuccinctRollup {
        AcceleratedSuccinctRollup::new(
            WgpuWaveletFreeze::new(&Default::default()),
            GPU_SUCCINCT_MIN_INPUT_ROWS,
        )
    }

    #[cfg(not(feature = "gpu-succinct"))]
    pub(super) fn archive_succinct_rollup() -> ArchiveSuccinctRollup {
        SuccinctRollup::new()
    }

    pub(super) fn validate_physical_leaf_boundaries(bytes: &[u8]) -> Result<()> {
        debug_assert_eq!(bytes.len() % 64, 0);
        let trible_count = bytes.len() / 64;
        for boundary in
            (INDEX_PHYSICAL_LEAF_TRIBLES..trible_count).step_by(INDEX_PHYSICAL_LEAF_TRIBLES)
        {
            let previous = &bytes[(boundary - 1) * 64..boundary * 64];
            let next = &bytes[boundary * 64..(boundary + 1) * 64];
            if previous == next {
                bail!("redundant trible across physical shard boundary {boundary}");
            }
            if previous > next {
                bail!("noncanonical ordering across physical shard boundary {boundary}");
            }
        }
        Ok(())
    }

    fn acquire_or_force(id: Id) -> ExclusiveId {
        id.acquire().unwrap_or_else(|| ExclusiveId::force(id))
    }

    pub fn parse_paths_parallel<T, F>(
        label: &str,
        paths: &[PathBuf],
        parse_one: F,
    ) -> Result<Vec<(PathBuf, Result<T>)>>
    where
        T: Send,
        F: Fn(&Path) -> Result<T> + Send + Sync,
    {
        let _span = info_span!("parallel_parse", label = label, files = paths.len()).entered();
        let total_files = paths.len();
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let parser_pool = ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .with_context(|| format!("build {label} parser thread pool"))?;
        let parse_start = std::time::Instant::now();
        println!(
            "{label} phase parse: {} file(s) using {} thread(s)",
            total_files, threads
        );
        let parsed_files = parser_pool.install(|| {
            paths
                .par_iter()
                .map(|path| {
                    let _file_span = info_span!(
                        "parse_file",
                        label = label,
                        path = %path.display()
                    )
                    .entered();
                    (path.to_path_buf(), parse_one(path.as_path()))
                })
                .collect()
        });
        let elapsed = parse_start.elapsed();
        println!("{label} phase parse: done in {:?}", elapsed);
        tracing::info!(
            label = label,
            files = total_files,
            threads = threads,
            elapsed_ms = elapsed.as_millis() as u64,
            "parallel parse complete"
        );
        Ok(parsed_files)
    }

    pub fn open_repo_for_write(
        pile_path: &Path,
        branch_id: Id,
        _branch_name: &str,
    ) -> Result<(Repo, Id)> {
        let mut repo = open_repo(pile_path)?;
        install_archive_index_hook(&mut repo, branch_id);
        Ok((repo, branch_id))
    }

    fn install_archive_index_hook(repo: &mut Repo, archive_branch: Id) {
        // Delay backend construction until this repository actually pushes
        // the archive branch. Other write lifecycles (notably replay cursor
        // updates) share this opener but never need an indexing backend.
        let mut succinct = None;
        repo.on_commit(move |storage, pushed_branch, batch, head_meta| {
            if pushed_branch != archive_branch {
                return Ok(());
            }
            let succinct = succinct.get_or_insert_with(archive_succinct_rollup);
            index_archive_batch(storage, batch, succinct, head_meta).map_err(|err| {
                Box::new(std::io::Error::other(format!("{err:#}")))
                    as Box<dyn std::error::Error + Send + Sync>
            })
        });
    }

    fn index_archive_batch<K>(
        storage: &mut Pile,
        batch: &CommitBatch,
        succinct: &K,
        head_meta: &mut TribleSet,
    ) -> Result<()>
    where
        K: IndexKind,
    {
        let content_attr = archive::content.id();
        let bm25_reader = storage
            .reader()
            .map_err(|err| anyhow!("open BM25 content reader: {err:?}"))?;
        let bm25 = Bm25Rollup::new(bm25_reader, content_attr);

        for kind in [succinct.kind_id(), bm25.kind_id()] {
            let manifest = Manifest::from_tribles(head_meta, kind);
            if !manifest.covers_head(batch.base_head) {
                return Err(anyhow!(
                    "archive index {kind:x} is stale at {:?}, expected base {:?}; run `archive index`",
                    manifest.covered,
                    batch.base_head
                ));
            }
        }

        for commit in &batch.commits {
            index_archive_commit(storage, *commit, succinct, &bm25, head_meta)?;
        }

        // Both recipes live in one hook scratch set, so these certificates
        // and both manifests either land together in the branch CAS or not at
        // all. Contentless merge commits still advance the certificates.
        set_coverage(head_meta, succinct.kind_id(), vec![batch.new_head]);
        set_coverage(head_meta, bm25.kind_id(), vec![batch.new_head]);
        Ok(())
    }

    pub(super) fn index_archive_commit<R, K>(
        storage: &mut Pile,
        commit: CommitHandle,
        succinct: &K,
        bm25: &Bm25Rollup<R>,
        head_meta: &mut TribleSet,
    ) -> Result<()>
    where
        R: triblespace::core::repo::BlobStoreGet,
        K: IndexKind,
    {
        let reader = storage
            .reader()
            .map_err(|err| anyhow!("open commit reader: {err:?}"))?;
        let commit_meta: TribleSet = reader
            .get(commit)
            .map_err(|err| anyhow!("load commit {commit:?}: {err:?}"))?;
        let content_handle = find!(
            (content_handle: Inline<Handle<SimpleArchive>>),
            pattern!(&commit_meta, [{ triblespace::core::repo::content: ?content_handle }])
        )
        .at_most_one()
        .map_err(|_| anyhow!("commit {commit:?} has ambiguous content"))?
        .map(|(handle,)| handle);
        let Some(content_handle) = content_handle else {
            return Ok(());
        };
        let source: Blob<SimpleArchive> = reader
            .get(content_handle)
            .map_err(|err| anyhow!("load content of commit {commit:?}: {err:?}"))?;
        if source.bytes.len() % 64 != 0 {
            return Err(anyhow!(
                "commit {commit:?} has malformed SimpleArchive length"
            ));
        }

        validate_physical_leaf_boundaries(&source.bytes)
            .with_context(|| format!("commit {commit:?} has malformed SimpleArchive"))?;
        let trible_count = source.bytes.len() / 64;
        for start in (0..trible_count).step_by(INDEX_PHYSICAL_LEAF_TRIBLES) {
            let end = (start + INDEX_PHYSICAL_LEAF_TRIBLES).min(trible_count);
            let bytes = source.bytes.slice(start * 64..end * 64);
            let chunk: TribleSet = Blob::<SimpleArchive>::new(bytes)
                .try_from_blob()
                .map_err(|err| anyhow!("decode commit {commit:?} shard: {err}"))?;

            append_segment(storage, succinct, &chunk, head_meta)
                .map_err(|err| anyhow!("append Succinct leaf for {commit:?}: {err}"))?;

            let mut content = TribleSet::new();
            for trible in chunk
                .iter()
                .filter(|trible| *trible.a() == archive::content.id())
            {
                let handle = *trible.v::<Handle<LongString>>();
                let _: View<str> = reader.get(handle).map_err(|err| {
                    anyhow!(
                        "archive content {:?} in commit {commit:?} is unreadable: {err:?}",
                        handle.raw
                    )
                })?;
                content.insert(trible);
            }
            if !content.is_empty() {
                append_segment(storage, bm25, &content, head_meta)
                    .map_err(|err| anyhow!("append BM25 leaf for {commit:?}: {err}"))?;
            }
        }
        Ok(())
    }

    pub fn open_repo_for_read(
        pile_path: &Path,
        branch_id: Id,
        branch_name: &str,
    ) -> Result<(Repo, Id)> {
        let mut repo = open_repo(pile_path)?;
        let res = validate_branch_for_read(&mut repo, branch_id, branch_name);
        if let Err(err) = res {
            let _ = repo.close();
            return Err(err);
        }
        Ok((repo, branch_id))
    }

    pub fn open_repo(pile_path: &Path) -> Result<Repo> {
        let open_start = std::time::Instant::now();
        let mut pile = Pile::open(pile_path).map_err(|e| anyhow!("open pile: {e:?}"))?;
        tracing::info!(
            elapsed_ms = open_start.elapsed().as_millis() as u64,
            "pile mmap open complete"
        );
        let refresh_start = std::time::Instant::now();
        if let Err(err) = pile.refresh() {
            // Avoid Drop warnings on early errors.
            let _ = pile.close();
            return Err(match err {
                triblespace::core::repo::pile::ReadError::CorruptPile { valid_length } => anyhow!(
                    "pile corrupt at byte {valid_length}: refusing to auto-repair (a stale binary \
                     could truncate newer data). If, and only if, the tail is a genuinely torn write, truncate it explicitly (DESTRUCTIVE) with: trible pile amputate {}",
                    pile_path.display()
                ),
                other => anyhow!("refresh pile {}: {other:?}", pile_path.display()),
            });
        }
        tracing::info!(
            elapsed_ms = refresh_start.elapsed().as_millis() as u64,
            "pile record refresh complete"
        );
        let repository_start = std::time::Instant::now();
        let signing_key = SigningKey::generate(&mut OsRng);
        let repo = Repository::new(pile, signing_key, TribleSet::new())
            .map_err(|err| anyhow!("create repository: {err:?}"))?;
        tracing::info!(
            elapsed_ms = repository_start.elapsed().as_millis() as u64,
            "repository construction complete"
        );
        Ok(repo)
    }

    pub fn validate_branch_for_read(
        repo: &mut Repo,
        branch_id: Id,
        branch_name: &str,
    ) -> Result<()> {
        if repo
            .storage_mut()
            .head(branch_id)
            .map_err(|e| anyhow!("branch head {branch_name}: {e:?}"))?
            .is_none()
        {
            return Err(anyhow!("unknown branch {branch_name} ({branch_id:x})"));
        }
        Ok(())
    }

    pub fn with_repo<T>(pile: &Path, f: impl FnOnce(&mut Repo) -> Result<T>) -> Result<T> {
        let mut repo = open_repo(pile)?;
        let result = f(&mut repo);
        let close_res = repo.close().map_err(|e| anyhow!("close pile: {e:?}"));
        if let Err(err) = close_res {
            if result.is_ok() {
                return Err(err);
            }
            eprintln!("warning: failed to close pile cleanly: {err:#}");
        }
        result
    }

    pub fn push_workspace(repo: &mut Repo, ws: &mut Ws) -> Result<()> {
        while let Some(mut conflict) = repo
            .try_push(ws)
            .map_err(|e| anyhow!("push workspace: {e:?}"))?
        {
            conflict
                .merge(ws)
                .map_err(|e| anyhow!("merge workspace: {e:?}"))?;
            *ws = conflict;
        }
        for failure in repo.take_hook_errors() {
            eprintln!(
                "warning: archive commit landed but derived indexes remain stale on branch {:x}: {}",
                failure.branch, failure.error
            );
        }
        Ok(())
    }

    pub fn refresh_catalog(
        ws: &mut Ws,
        catalog: &mut TribleSet,
        catalog_head: &mut Option<CommitHandle>,
    ) -> Result<()> {
        let next_head = ws.head();
        if *catalog_head == next_head {
            return Ok(());
        }

        let delta = ws
            .checkout(*catalog_head..next_head)
            .context("checkout workspace delta")?;
        if !delta.is_empty() {
            *catalog += delta.into_facts();
        }
        *catalog_head = next_head;
        Ok(())
    }

    pub fn commit_delta(
        repo: &mut Repo,
        ws: &mut Ws,
        catalog: &mut TribleSet,
        catalog_head: &mut Option<CommitHandle>,
        change: TribleSet,
        message: &'static str,
    ) -> Result<bool> {
        if change.is_empty() {
            return Ok(false);
        }

        let delta = change.difference(catalog);
        if delta.is_empty() {
            return Ok(false);
        }

        ws.commit(delta, message);
        push_workspace(repo, ws).with_context(|| format!("push {message}"))?;
        refresh_catalog(ws, catalog, catalog_head)
            .with_context(|| format!("refresh catalog after {message}"))?;
        Ok(true)
    }

    pub fn now_epoch() -> Epoch {
        Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
    }

    pub fn unknown_epoch() -> Epoch {
        Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0)
    }

    pub fn epoch_from_seconds(value: f64) -> Option<Epoch> {
        if value.is_finite() {
            Some(Epoch::from_unix_seconds(value))
        } else {
            None
        }
    }

    pub fn epoch_interval(epoch: Epoch) -> Inline<NsTAIInterval> {
        (epoch, epoch).try_to_inline().unwrap()
    }

    pub fn ensure_author(
        ws: &mut Ws,
        catalog: &TribleSet,
        name: &str,
        role: &str,
    ) -> Result<(Id, TribleSet)> {
        if let Some(author_id) = find_author_by_name(ws, catalog, name)? {
            let mut change = TribleSet::new();
            if author_role_handle(catalog, author_id).is_none() && !role.is_empty() {
                let handle = ws.put(role.to_owned());
                let author_entity = acquire_or_force(author_id);
                change += entity! { &author_entity @
                    archive::author_role: handle
                };
            }
            return Ok((author_id, change));
        }

        // Identity = kind + name, content-derived via entity!'s intrinsic
        // rooting: the same author name mints the same id in every pile and
        // every run, so re-imports and cross-pile merges converge instead of
        // forking (same mechanism as wiki's deterministic version/tag ids).
        // Role is volatile metadata and merges onto the id afterwards; the
        // per-message ground truth lives in import_schema::source_role anyway.
        let name_handle = ws.put(name.to_owned());
        let author_fragment = entity! { _ @
            metadata::tag: archive::kind_author,
            archive::author_name: name_handle,
        };
        let author_id = author_fragment
            .root()
            .expect("entity! must export a single root id");
        let mut change = TribleSet::new();
        change += author_fragment;
        if !role.is_empty() {
            let role_handle = ws.put(role.to_owned());
            let author_entity = acquire_or_force(author_id);
            change += entity! { &author_entity @
                archive::author_role: role_handle,
            };
        }
        Ok((author_id, change))
    }

    fn find_author_by_name(
        ws: &mut Ws,
        catalog: &TribleSet,
        target_name: &str,
    ) -> Result<Option<Id>> {
        for (author_id, name_handle) in find!(
            (author: Id, author_name: Inline<Handle<LongString>>),
            pattern!(catalog, [{
                ?author @
                metadata::tag: archive::kind_author,
                archive::author_name: ?author_name,
            }])
        ) {
            let existing: View<str> = ws.get(name_handle).context("load author name")?;
            if existing.as_ref() == target_name {
                return Ok(Some(author_id));
            }
        }
        Ok(None)
    }

    fn author_role_handle(
        catalog: &TribleSet,
        author_id: Id,
    ) -> Option<Inline<Handle<LongString>>> {
        for (author, role) in find!(
            (author: Id, role: Inline<Handle<LongString>>),
            pattern!(catalog, [{ ?author @ archive::author_role: ?role }])
        ) {
            if author == author_id {
                return Some(role);
            }
        }
        None
    }
}

#[cfg(test)]
mod index_leaf_tests {
    use super::common::validate_physical_leaf_boundaries;

    const LEAF_TRIBLES: usize = 1 << 16;

    #[test]
    fn physical_leaf_boundaries_preserve_global_canonical_order() {
        let mut bytes = vec![0u8; (LEAF_TRIBLES + 1) * 64];
        let previous = (LEAF_TRIBLES - 1) * 64;
        let next = LEAF_TRIBLES * 64;

        bytes[previous] = 1;
        bytes[next] = 2;
        validate_physical_leaf_boundaries(&bytes).unwrap();

        bytes[next] = 1;
        assert!(validate_physical_leaf_boundaries(&bytes)
            .unwrap_err()
            .to_string()
            .contains("redundant"));

        bytes[next] = 0;
        assert!(validate_physical_leaf_boundaries(&bytes)
            .unwrap_err()
            .to_string()
            .contains("noncanonical"));
    }
}

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "archive", about = "Query imported archives in TribleSpace")]
struct Cli {
    /// Path to the pile file to query.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch name to query.
    #[arg(long, default_value = "archive")]
    branch: String,
    /// Branch id to query (hex). Overrides config/env branch id.
    #[arg(long)]
    branch_id: Option<String>,
    /// Enable tracing spans for importer and search profiling.
    #[arg(long)]
    trace: bool,
    /// Optional tracing filter (defaults to `info`).
    #[arg(long)]
    trace_filter: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Import external archives into the archive branch.
    Import {
        #[arg(value_enum)]
        source: ImportSource,
        /// Optional path override for this source (or backup root for `all`).
        path: Option<PathBuf>,
    },
    /// List the most recent messages.
    List {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Show one message by id prefix.
    Show { id: String },
    /// Show a reply_to chain ending at the given message id prefix.
    Thread {
        id: String,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Search message content (BM25-ranked via the index; see `--exact`).
    Search {
        #[arg(help = "Query text. Use @path for file input or @- for stdin.")]
        text: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Use case-sensitive matching (implies --exact).
        #[arg(long)]
        case_sensitive: bool,
        /// Exact substring scan over every message blob instead of the
        /// BM25 index — slow at archive scale, but needs no index.
        #[arg(long)]
        exact: bool,
    },
    /// Build or repair the Succinct and BM25 LSM indexes.
    /// Replays only uncovered commits and checkpoints after each one, so an
    /// interrupted run resumes without rebuilding already-covered history.
    Index,
    /// List imported conversations.
    Imports {
        format: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Replay the archive as ONE interleaved temporal stream — the comb's
    /// reading instrument. All conversations from all sources merge into a
    /// single chronological view (one being, one timeline). Dialogue only by
    /// default: tool/system exhaust is skipped, since its effect already
    /// lives inside the dialogue's own words.
    ///
    /// `archive replay start <from>` begins (or restarts) at a timestamp;
    /// bare `archive replay` emits the next batch and advances the cursor;
    /// `archive replay stop` clears the cursor. Cursors are persona-scoped
    /// session bookkeeping (append-only, latest-wins) — the archive itself
    /// is never scoped.
    Replay {
        /// `start <from-ts>`, `stop`, or nothing for the next batch.
        #[arg(value_name = "ACTION")]
        action: Vec<String>,
        /// Messages per batch (a batch extends past the limit to finish
        /// equal-timestamp runs, so the cursor can be strictly-greater).
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Include tool/system exhaust (deliberate evidence consultation,
        /// not part of the memory act).
        #[arg(long)]
        with_tools: bool,
        /// Cursor owner. No default label on purpose: cursors are session
        /// bookkeeping, and no zooid is baked in as "the" rememberer.
        #[arg(long, env = "PERSONA")]
        persona: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ImportSource {
    Chatgpt,
    Codex,
    Copilot,
    Gemini,
    ClaudeCode,
    ClaudeWeb,
    Agy,
    All,
}

impl ImportSource {
    fn label(self) -> &'static str {
        match self {
            ImportSource::Chatgpt => "chatgpt",
            ImportSource::Codex => "codex",
            ImportSource::Copilot => "copilot",
            ImportSource::Gemini => "gemini",
            ImportSource::ClaudeCode => "claude-code",
            ImportSource::ClaudeWeb => "claude-web",
            ImportSource::Agy => "agy",
            ImportSource::All => "all",
        }
    }
}

#[derive(Debug, Clone)]
struct ImportJob {
    source: ImportSource,
    path: PathBuf,
}

fn default_source_path(source: ImportSource, base: &Path) -> PathBuf {
    match source {
        ImportSource::Chatgpt => base.to_path_buf(),
        ImportSource::Codex => base.join("codex"),
        ImportSource::Copilot => base.join("copilot"),
        ImportSource::Gemini => {
            base.join("gemini/Takeout/My Activity/Gemini Apps/My Activity.html")
        }
        ImportSource::ClaudeCode => base.join("claude-code"),
        ImportSource::ClaudeWeb => base.join("claude-web"),
        ImportSource::Agy => base.join("agy"),
        ImportSource::All => base.to_path_buf(),
    }
}

fn resolve_import_jobs(source: ImportSource, path: Option<&Path>) -> Result<Vec<ImportJob>> {
    match source {
        ImportSource::All => {
            let root = path
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("chatgptbackup"));
            Ok(vec![
                ImportJob {
                    source: ImportSource::Chatgpt,
                    path: default_source_path(ImportSource::Chatgpt, &root),
                },
                ImportJob {
                    source: ImportSource::Codex,
                    path: default_source_path(ImportSource::Codex, &root),
                },
                ImportJob {
                    source: ImportSource::Copilot,
                    path: default_source_path(ImportSource::Copilot, &root),
                },
                ImportJob {
                    source: ImportSource::Gemini,
                    path: default_source_path(ImportSource::Gemini, &root),
                },
                ImportJob {
                    source: ImportSource::ClaudeCode,
                    path: default_source_path(ImportSource::ClaudeCode, &root),
                },
                ImportJob {
                    source: ImportSource::ClaudeWeb,
                    path: default_source_path(ImportSource::ClaudeWeb, &root),
                },
                ImportJob {
                    source: ImportSource::Agy,
                    path: default_source_path(ImportSource::Agy, &root),
                },
            ])
        }
        one => Ok(vec![ImportJob {
            source: one,
            path: path
                .map(Path::to_path_buf)
                .unwrap_or_else(|| default_source_path(one, Path::new("chatgptbackup"))),
        }]),
    }
}

fn run_import_jobs(
    source: ImportSource,
    path: Option<&Path>,
    pile_path: &Path,
    branch_name: &str,
    branch_id: Id,
) -> Result<()> {
    let all_start = Instant::now();
    let jobs = resolve_import_jobs(source, path)?;
    let _span = info_span!(
        "archive_import",
        source = source.label(),
        jobs = jobs.len(),
        branch = branch_name,
        branch_id = %format!("{branch_id:x}"),
        pile = %pile_path.display()
    )
    .entered();
    println!(
        "archive import: {} job(s) -> {} ({:x}) on pile {}",
        jobs.len(),
        branch_name,
        branch_id,
        pile_path.display()
    );

    let total_jobs = jobs.len();
    for (job_index, job) in jobs.into_iter().enumerate() {
        let _job_span = info_span!(
            "archive_import_job",
            source = job.source.label(),
            job_index = job_index + 1,
            total_jobs = total_jobs,
            path = %job.path.display()
        )
        .entered();
        if source == ImportSource::All && !job.path.exists() {
            eprintln!(
                "skip {} import (path missing): {}",
                job.source.label(),
                job.path.display()
            );
            continue;
        }
        if !job.path.exists() {
            bail!(
                "{} import path not found: {}",
                job.source.label(),
                job.path.display()
            );
        }
        let job_start = Instant::now();
        println!(
            "archive import progress {}/{}: {} from {}",
            job_index + 1,
            total_jobs,
            job.source.label(),
            job.path.display()
        );
        match job.source {
            ImportSource::Chatgpt => archive_import_chatgpt::import_into_archive(
                &job.path,
                pile_path,
                branch_name,
                branch_id,
            ),
            ImportSource::Codex => archive_import_codex::import_into_archive(
                &job.path,
                pile_path,
                branch_name,
                branch_id,
            ),
            ImportSource::Copilot => archive_import_copilot::import_into_archive(
                &job.path,
                pile_path,
                branch_name,
                branch_id,
            ),
            ImportSource::Gemini => archive_import_gemini::import_into_archive(
                &job.path,
                pile_path,
                branch_name,
                branch_id,
            ),
            ImportSource::ClaudeCode => archive_import_claude_code::import_into_archive(
                &job.path,
                pile_path,
                branch_name,
                branch_id,
            ),
            ImportSource::ClaudeWeb => archive_import_claude_web::import_into_archive(
                &job.path,
                pile_path,
                branch_name,
                branch_id,
            ),
            ImportSource::Agy => archive_import_agy::import_into_archive(
                &job.path,
                pile_path,
                branch_name,
                branch_id,
            ),
            ImportSource::All => Ok(()),
        }
        .with_context(|| {
            format!(
                "run {} importer for {}",
                job.source.label(),
                job.path.display()
            )
        })?;
        println!(
            "archive import done {}/{}: {} in {:?}",
            job_index + 1,
            total_jobs,
            job.source.label(),
            job_start.elapsed()
        );
        tracing::info!(
            source = job.source.label(),
            job_index = job_index + 1,
            total_jobs = total_jobs,
            elapsed_ms = job_start.elapsed().as_millis() as u64,
            "archive import job complete"
        );
    }

    let total_elapsed = all_start.elapsed();
    println!("archive import all jobs done in {:?}", total_elapsed);
    tracing::info!(
        source = source.label(),
        jobs = total_jobs,
        elapsed_ms = total_elapsed.as_millis() as u64,
        "archive import complete"
    );

    Ok(())
}

fn init_tracing(enabled: bool, filter: Option<&str>) {
    static TRACE_INIT: Once = Once::new();
    if !enabled {
        return;
    }

    TRACE_INIT.call_once(|| {
        let env_filter = filter
            .map(EnvFilter::new)
            .or_else(|| {
                std::env::var("PLAYGROUND_ARCHIVE_TRACE_FILTER")
                    .ok()
                    .map(EnvFilter::new)
            })
            .unwrap_or_else(|| EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_target(false)
            .without_time()
            .with_env_filter(env_filter)
            .with_span_events(FmtSpan::CLOSE)
            .try_init();
        tracing::info!("archive tracing enabled");
    });
}

fn interval_key(interval: Inline<NsTAIInterval>) -> i128 {
    let (lower, _upper): (Epoch, Epoch) = interval.try_from_inline().unwrap();
    lower.to_tai_duration().total_nanoseconds()
}

fn load_longstring(
    ws: &mut common::Ws,
    handle: Inline<Handle<LongString>>,
) -> Result<String> {
    let view: View<str> = ws.get(handle).context("read longstring")?;
    Ok(view.to_string())
}

fn u256be_to_u64(value: Inline<U256BE>) -> Option<u64> {
    let raw = value.raw;
    if raw[..24].iter().any(|byte| *byte != 0) {
        return None;
    }
    let bytes: [u8; 8] = raw[24..32].try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

fn author_name(ws: &mut common::Ws, catalog: &TribleSet, author_id: Id) -> Result<String> {
    let Some(handle) = find!(
        (handle: Inline<Handle<LongString>>),
        pattern!(catalog, [{ author_id @ common::archive::author_name: ?handle }])
    )
    .into_iter()
    .next()
    .map(|(h,)| h) else {
        return Ok("<unknown>".to_string());
    };
    load_longstring(ws, handle)
}

fn author_role(ws: &mut common::Ws, catalog: &TribleSet, author_id: Id) -> Result<Option<String>> {
    let Some(handle) = find!(
        (handle: Inline<Handle<LongString>>),
        pattern!(catalog, [{ author_id @ common::archive::author_role: ?handle }])
    )
    .into_iter()
    .next()
    .map(|(h,)| h) else {
        return Ok(None);
    };
    Ok(Some(load_longstring(ws, handle)?))
}

fn message_content_type(catalog: &TribleSet, message_id: Id) -> Option<String> {
    find!(
        (content_type: String),
        pattern!(catalog, [{ message_id @ common::archive::content_type: ?content_type }])
    )
    .into_iter()
    .next()
    .map(|(ct,)| ct)
}

#[derive(Debug, Clone)]
struct AttachmentRecord {
    id: Id,
    source_id: Option<String>,
    name: Option<String>,
    mime: Option<String>,
    size_bytes: Option<u64>,
    width_px: Option<u64>,
    height_px: Option<u64>,
    has_data: bool,
}

fn message_attachments(
    ws: &mut common::Ws,
    catalog: &TribleSet,
    message_id: Id,
) -> Result<Vec<AttachmentRecord>> {
    let mut attachments: Vec<Id> = find!(
        (attachment: Id),
        pattern!(catalog, [{ message_id @ common::archive::attachment: ?attachment }])
    )
    .into_iter()
    .map(|(a,)| a)
    .collect();
    attachments.sort();
    attachments.dedup();

    // Batch-query each attribute across ALL attachments at once (7 queries total
    // instead of 7*N).
    let source_ids: HashMap<Id, Inline<Handle<LongString>>> = find!(
        (att: Id, handle: Inline<Handle<LongString>>),
        pattern!(catalog, [{
            message_id @ common::archive::attachment: ?att,
        }, {
            ?att @ common::archive::attachment_source_id: ?handle,
        }])
    )
    .into_iter()
    .collect();

    let names: HashMap<Id, Inline<Handle<LongString>>> = find!(
        (att: Id, handle: Inline<Handle<LongString>>),
        pattern!(catalog, [{
            message_id @ common::archive::attachment: ?att,
        }, {
            ?att @ common::archive::attachment_name: ?handle,
        }])
    )
    .into_iter()
    .collect();

    let mimes: HashMap<Id, String> = find!(
        (att: Id, mime: String),
        pattern!(catalog, [{
            message_id @ common::archive::attachment: ?att,
        }, {
            ?att @ common::archive::attachment_mime: ?mime,
        }])
    )
    .into_iter()
    .collect();

    let sizes: HashMap<Id, Inline<U256BE>> = find!(
        (att: Id, size: Inline<U256BE>),
        pattern!(catalog, [{
            message_id @ common::archive::attachment: ?att,
        }, {
            ?att @ common::archive::attachment_size_bytes: ?size,
        }])
    )
    .into_iter()
    .collect();

    let widths: HashMap<Id, Inline<U256BE>> = find!(
        (att: Id, width: Inline<U256BE>),
        pattern!(catalog, [{
            message_id @ common::archive::attachment: ?att,
        }, {
            ?att @ common::archive::attachment_width_px: ?width,
        }])
    )
    .into_iter()
    .collect();

    let heights: HashMap<Id, Inline<U256BE>> = find!(
        (att: Id, height: Inline<U256BE>),
        pattern!(catalog, [{
            message_id @ common::archive::attachment: ?att,
        }, {
            ?att @ common::archive::attachment_height_px: ?height,
        }])
    )
    .into_iter()
    .collect();

    let has_data_set: HashSet<Id> = find!(
        (att: Id),
        pattern!(catalog, [{
            message_id @ common::archive::attachment: ?att,
        }, {
            ?att @ common::archive::attachment_data: _?handle,
        }])
    )
    .into_iter()
    .map(|(a,)| a)
    .collect();

    let mut out = Vec::new();
    for attachment_id in attachments {
        let source_id = match source_ids.get(&attachment_id) {
            Some(&h) => Some(load_longstring(ws, h)?),
            None => None,
        };
        let name = match names.get(&attachment_id) {
            Some(&h) => Some(load_longstring(ws, h)?),
            None => None,
        };

        out.push(AttachmentRecord {
            id: attachment_id,
            source_id,
            name,
            mime: mimes.get(&attachment_id).cloned(),
            size_bytes: sizes.get(&attachment_id).and_then(|&s| u256be_to_u64(s)),
            width_px: widths.get(&attachment_id).and_then(|&w| u256be_to_u64(w)),
            height_px: heights.get(&attachment_id).and_then(|&h| u256be_to_u64(h)),
            has_data: has_data_set.contains(&attachment_id),
        });
    }
    Ok(out)
}

fn resolve_message_id(catalog: &TribleSet, prefix: &str) -> Result<Id> {
    let candidates = find!(
        message: Id,
        pattern!(catalog, [{
            ?message @ common::metadata::tag: common::archive::kind_message,
        }])
    );
    faculties::resolve_id_prefix(prefix, candidates)
}

fn message_record(
    ws: &mut common::Ws,
    catalog: &TribleSet,
    message_id: Id,
) -> Result<(
    Id,
    String,
    Option<String>,
    Inline<NsTAIInterval>,
    Inline<Handle<LongString>>,
    Option<Id>,
)> {
    let Some((author_id, content_handle, created_at)) = find!(
        (
            author: Id,
            content: Inline<Handle<LongString>>,
            created_at: Inline<NsTAIInterval>
        ),
        pattern!(catalog, [{
            message_id @
                common::archive::author: ?author,
                common::archive::content: ?content,
                common::metadata::created_at: ?created_at,
        }])
    )
    .into_iter()
    .next()
    .map(|(a, c, t)| (a, c, t)) else {
        return Err(anyhow!("message {message_id:x} missing required fields"));
    };

    let reply_to = find!(
        (parent: Id),
        pattern!(catalog, [{ message_id @ common::archive::reply_to: ?parent }])
    )
    .into_iter()
    .next()
    .map(|(p,)| p);

    let name = author_name(ws, catalog, author_id)?;
    let role = author_role(ws, catalog, author_id)?;
    Ok((message_id, name, role, created_at, content_handle, reply_to))
}

// ---------------------------------------------------------------------------
// replay — the comb's reading instrument
// ---------------------------------------------------------------------------

/// Parse "YYYY-MM-DDTHH:MM:SS" as TAI.
fn parse_tai_timestamp(s: &str) -> Result<Epoch> {
    let parts: Vec<&str> = s.split('T').collect();
    if parts.len() != 2 {
        bail!("invalid timestamp (expected YYYY-MM-DDTHH:MM:SS): {s}");
    }
    let date: Vec<&str> = parts[0].split('-').collect();
    let time: Vec<&str> = parts[1].split(':').collect();
    if date.len() != 3 || time.len() != 3 {
        bail!("invalid timestamp (expected YYYY-MM-DDTHH:MM:SS): {s}");
    }
    Ok(Epoch::from_gregorian_tai(
        date[0].parse().context("year")?,
        date[1].parse().context("month")?,
        date[2].parse().context("day")?,
        time[0].parse().context("hour")?,
        time[1].parse().context("minute")?,
        time[2].parse().context("second")?,
        0,
    ))
}

/// Append a cursor advance (or a stop marker when `position` is None) via
/// the shared comb helpers (faculties::schemas::memory::comb).
fn write_cursor(
    repo: &mut common::Repo,
    branch_id: Id,
    stream: &str,
    persona: &str,
    position: Option<Epoch>,
) -> Result<()> {
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull for cursor write: {e:?}"))?;
    let change =
        common::comb::advance_change(stream, persona, position, None, common::now_epoch());
    ws.commit(change, "archive replay cursor");
    common::push_workspace(repo, &mut ws)
}

/// Conversation label for a message: "source · title-or-id-prefix".
fn conversation_label(
    ws: &mut common::Ws,
    catalog: &TribleSet,
    message_id: Id,
    cache: &mut HashMap<Id, String>,
) -> Result<String> {
    // Forward edge (most importers) then reverse edge (claude-code).
    let convo = find!(
        c: Id,
        pattern!(catalog, [{ message_id @ common::import_schema::conversation: ?c }])
    )
    .next()
    .or_else(|| {
        find!(
            c: Id,
            pattern!(catalog, [{ ?c @ common::import_schema::message: message_id }])
        )
        .next()
    });
    let Some(convo) = convo else {
        return Ok("?".to_string());
    };
    if let Some(label) = cache.get(&convo) {
        return Ok(label.clone());
    }
    let format = find!(
        f: String,
        pattern!(catalog, [{ convo @ common::import_schema::source_format: ?f }])
    )
    .next()
    .unwrap_or_else(|| "?".to_string());
    let title = find!(
        t: Inline<Handle<LongString>>,
        pattern!(catalog, [{ convo @ common::import_schema::source_conversation_title: ?t }])
    )
    .next()
    .map(|h| load_longstring(ws, h))
    .transpose()?;
    let label = match title {
        Some(title) if !title.is_empty() => format!("{format} · {title}"),
        _ => {
            let source_id = find!(
                s: Inline<Handle<LongString>>,
                pattern!(catalog, [{ convo @ common::import_schema::source_conversation_id: ?s }])
            )
            .next()
            .map(|h| load_longstring(ws, h))
            .transpose()?
            .unwrap_or_default();
            let prefix: String = source_id.chars().take(8).collect();
            format!("{format} · {prefix}")
        }
    };
    cache.insert(convo, label.clone());
    Ok(label)
}

const REPLAY_STREAM: &str = "archive-replay";

/// Cursors live on their own tiny branch: per-batch reads stay instant, and
/// the archive branch remains pure evidence — no practice state mixed in.
const COMB_STATE_BRANCH: &str = "comb-state";

/// One replay record in the disk index. The index is a disposable cache of
/// the dialogue timeline (the pile remains the truth): rebuilt only when the
/// archive branch head changes, i.e. after imports.
#[derive(serde::Serialize, serde::Deserialize)]
struct ReplayRecord {
    /// interval_key of created_at — the timeline coordinate.
    k: i128,
    /// Display timestamp.
    w: String,
    /// Conversation label ("source · title-or-id").
    l: String,
    /// Author display name.
    n: String,
    /// Author role ("" when unknown) — tool/system filtering happens at
    /// read time so one index serves both modes.
    r: String,
    /// Message content text.
    c: String,
}

fn replay_index_path(pile_path: &Path) -> PathBuf {
    let mut name = pile_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "pile".to_string());
    name.push_str(".replay-index.jsonl");
    pile_path.with_file_name(name)
}

/// Build the timeline index from the archive branch (the expensive pass:
/// full checkout of the evidence). Returns the number of records written.
fn build_replay_index(
    repo: &mut common::Repo,
    archive_branch_id: Id,
    head_key: &str,
    path: &Path,
) -> Result<usize> {
    eprintln!("replay index stale — rebuilding (full evidence checkout; this is the slow pass)...");
    let mut ws = repo
        .pull(archive_branch_id)
        .map_err(|e| anyhow!("pull archive branch: {e:?}"))?;
    let catalog = ws.checkout(..).context("checkout archive branch")?;

    let mut author_names: HashMap<Id, String> = HashMap::new();
    let mut author_roles: HashMap<Id, String> = HashMap::new();
    for (author_id, name_handle) in find!(
        (a: Id, n: Inline<Handle<LongString>>),
        pattern!(&catalog, [{
            ?a @
                common::metadata::tag: common::archive::kind_author,
                common::archive::author_name: ?n,
        }])
    ) {
        author_names.insert(author_id, load_longstring(&mut ws, name_handle)?);
    }
    for (author_id, role_handle) in find!(
        (a: Id, r: Inline<Handle<LongString>>),
        pattern!(&catalog, [{
            ?a @
                common::metadata::tag: common::archive::kind_author,
                common::archive::author_role: ?r,
        }])
    ) {
        author_roles.insert(author_id, load_longstring(&mut ws, role_handle)?);
    }

    let mut records: Vec<(i128, Id, Id, Inline<Handle<LongString>>)> = Vec::new();
    for (message_id, author_id, content_handle, created_at) in find!(
        (
            message: Id,
            author: Id,
            content: Inline<Handle<LongString>>,
            created_at: Inline<NsTAIInterval>
        ),
        pattern!(&catalog, [{
            ?message @
                common::metadata::tag: common::archive::kind_message,
                common::archive::author: ?author,
                common::archive::content: ?content,
                common::metadata::created_at: ?created_at,
        }])
    ) {
        records.push((
            interval_key(created_at),
            message_id,
            author_id,
            content_handle,
        ));
    }
    records.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut convo_cache: HashMap<Id, String> = HashMap::new();
    let file = std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut out = std::io::BufWriter::new(file);
    use std::io::Write as _;
    writeln!(out, "{head_key}")?;
    let total = records.len();
    for (i, (key, message_id, author_id, content_handle)) in records.into_iter().enumerate() {
        let content = load_longstring(&mut ws, content_handle)?;
        let label = conversation_label(&mut ws, &catalog, message_id, &mut convo_cache)?;
        let when = {
            let e = Epoch::from_tai_duration(hifitime::Duration::from_total_nanoseconds(key));
            let (y, m, d, hh, mm, ss, _) = e.to_gregorian_tai();
            format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}")
        };
        let record = ReplayRecord {
            k: key,
            w: when,
            l: label,
            n: author_names.get(&author_id).cloned().unwrap_or_default(),
            r: author_roles.get(&author_id).cloned().unwrap_or_default(),
            c: content,
        };
        writeln!(out, "{}", serde_json::to_string(&record)?)?;
        if (i + 1) % 100_000 == 0 {
            eprintln!("  indexed {}/{}", i + 1, total);
        }
    }
    out.into_inner().context("flush index")?;
    Ok(total)
}

/// Replay is self-contained: it manages the comb-state branch (cursors) and
/// the disk index (timeline cache), touching the heavy archive branch only
/// when the index is stale.
fn run_replay_standalone(
    pile_path: &Path,
    archive_branch_id: Id,
    archive_branch_name: &str,
    action: &[String],
    limit: usize,
    with_tools: bool,
    persona: Option<&str>,
) -> Result<()> {
    let Some(persona) = persona else {
        bail!(
            "no persona: set $PERSONA or pass --persona.\n\
             Cursors are session bookkeeping — no zooid is defaulted as \
             \"the\" rememberer; the archive and the memories belong to \
             the one being."
        );
    };

    let (mut repo, archive_branch_id) =
        common::open_repo_for_write(pile_path, archive_branch_id, archive_branch_name)?;
    let res = (|| -> Result<()> {
        let comb_branch_id = repo
            .ensure_branch(COMB_STATE_BRANCH, None)
            .map_err(|e| anyhow!("ensure comb-state branch: {e:?}"))?;

        match action.first().map(String::as_str) {
            Some("start") => {
                let Some(raw) = action.get(1) else {
                    bail!("usage: archive replay start <YYYY-MM-DDTHH:MM:SS>");
                };
                let from = parse_tai_timestamp(raw)?;
                // Exclusive position one ns before the requested start, so
                // the first batch includes messages at exactly <from>.
                let position = from - hifitime::Duration::from_total_nanoseconds(1);
                write_cursor(&mut repo, comb_branch_id, REPLAY_STREAM, persona, Some(position))?;
                println!("replay started at {raw} (persona {persona})");
                return Ok(());
            }
            Some("stop") => {
                write_cursor(&mut repo, comb_branch_id, REPLAY_STREAM, persona, None)?;
                println!("replay stopped (persona {persona})");
                return Ok(());
            }
            Some(other) => bail!("unknown replay action `{other}` (start/stop or nothing)"),
            None => {}
        }

        // Cursor read: tiny branch, instant checkout.
        let comb_catalog = {
            let mut ws = repo
                .pull(comb_branch_id)
                .map_err(|e| anyhow!("pull comb-state branch: {e:?}"))?;
            ws.checkout(..).context("checkout comb-state branch")?
        };
        let Some((Some(position_key), _)) = common::comb::latest(&comb_catalog, REPLAY_STREAM, persona)
        else {
            bail!("no active replay for persona {persona}: use `archive replay start <from>`");
        };

        // Index freshness: keyed by the archive branch head.
        let head_key = {
            let head = repo
                .storage_mut()
                .head(archive_branch_id)
                .map_err(|e| anyhow!("archive branch head: {e:?}"))?;
            format!("{head:?}")
        };
        let index_path = replay_index_path(pile_path);
        let stale = match std::fs::File::open(&index_path) {
            Ok(file) => {
                let mut first = String::new();
                std::io::BufReader::new(file).read_line(&mut first)?;
                first.trim_end() != head_key
            }
            Err(_) => true,
        };
        if stale {
            let total = build_replay_index(&mut repo, archive_branch_id, &head_key, &index_path)?;
            eprintln!("replay index built: {total} message(s) at {}", index_path.display());
        }

        // Stream the index: filter, position, batch (extending through any
        // equal-timestamp run so the cursor stays strictly-greater), count.
        let file = std::fs::File::open(&index_path)
            .with_context(|| format!("open {}", index_path.display()))?;
        let reader = std::io::BufReader::new(file);
        let mut emitted = 0usize;
        let mut remaining = 0usize;
        let mut last_key = position_key;
        for (line_no, line) in reader.lines().enumerate() {
            let line = line?;
            if line_no == 0 || line.is_empty() {
                continue;
            }
            let record: ReplayRecord = serde_json::from_str(&line)
                .with_context(|| format!("parse index line {}", line_no + 1))?;
            if !with_tools && (record.r == "tool" || record.r == "system") {
                continue;
            }
            if record.k <= position_key {
                continue;
            }
            if emitted < limit || record.k == last_key {
                println!("── [{}] {} — {}:", record.w, record.l, record.n);
                println!("{}", record.c);
                println!();
                last_key = record.k;
                emitted += 1;
            } else {
                remaining += 1;
            }
        }

        if emitted == 0 {
            println!("replay complete: nothing after the cursor. The past is read.");
            return Ok(());
        }

        let last_epoch =
            Epoch::from_tai_duration(hifitime::Duration::from_total_nanoseconds(last_key));
        write_cursor(&mut repo, comb_branch_id, REPLAY_STREAM, persona, Some(last_epoch))?;
        println!(
            "— batch: {emitted} message(s); cursor → {last_epoch}; {remaining} remaining"
        );
        Ok(())
    })();

    let close_result = repo
        .close()
        .map_err(|e| anyhow!("close pile {}: {e:?}", pile_path.display()));
    match (res, close_result) {
        (Err(err), _) => Err(err),
        (Ok(()), Err(err)) => Err(err),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn snippet(text: &str, max: usize) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if out.chars().count() >= max {
            out.push_str("...");
            break;
        }
        if ch == '\n' || ch == '\r' {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

fn load_value_or_file(raw: &str, label: &str) -> Result<String> {
    if let Some(path) = raw.strip_prefix('@') {
        if path == "-" {
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .with_context(|| format!("read {label} from stdin"))?;
            return Ok(value);
        }
        return std::fs::read_to_string(path).with_context(|| format!("read {label} from {path}"));
    }
    Ok(raw.to_string())
}

/// Resolve one author's display name from a checkout-free trible index plus
/// one blob get for the name string.
fn author_name_from_index<P: TriblePattern>(
    ws: &mut common::Ws,
    index: &P,
    author_id: Id,
) -> Result<String> {
    let Some((handle,)) = find!(
        (handle: Inline<Handle<LongString>>),
        pattern!(index, [{ author_id @ common::archive::author_name: ?handle }])
    )
    .next() else {
        return Ok("<unknown>".to_string());
    };
    load_longstring(ws, handle)
}

/// Resolve one author's role from a checkout-free trible index, if present.
fn author_role_from_index<P: TriblePattern>(
    ws: &mut common::Ws,
    index: &P,
    author_id: Id,
) -> Result<Option<String>> {
    let Some((handle,)) = find!(
        (handle: Inline<Handle<LongString>>),
        pattern!(index, [{ author_id @ common::archive::author_role: ?handle }])
    )
    .next() else {
        return Ok(None);
    };
    Ok(Some(load_longstring(ws, handle)?))
}

/// Search is dispatched standalone so the fast BM25 path never pays the
/// full-branch `ws.checkout(..)` the other read commands do.
///
/// Fast path (default / BM25): attach the branch-head BM25 and Succinct
/// index-home segments, require both coverage certificates to equal the source
/// HEAD, rank via [`query_across`], then resolve each hit through the
/// cross-segment Succinct union. No checkout or monolithic content rollup is
/// involved.
///
/// `--exact` / `--case_sensitive` keep the substring scan, which is
/// inherently a full-content pass and still checks out the branch.
fn run_search_standalone(
    mut repo: common::Repo,
    pile_path: &Path,
    branch_id: Id,
    text: String,
    limit: usize,
    case_sensitive: bool,
    exact: bool,
) -> Result<()> {
    let text = load_value_or_file(&text, "search text")?;
    let res = (|| -> Result<()> {
        if exact || case_sensitive {
            return exact_scan(&mut repo, branch_id, &text, limit, case_sensitive);
        }

        // Read the mutable branch pin exactly once. The source HEAD and both
        // manifests below are therefore one consistent snapshot; attaching a
        // manifest never races by rereading the pin.
        let branch_meta_handle = repo
            .storage_mut()
            .head(branch_id)
            .map_err(|e| anyhow!("read archive branch head: {e:?}"))?
            .ok_or_else(|| anyhow!("archive branch is missing"))?;
        let branch_reader = repo
            .storage_mut()
            .reader()
            .map_err(|e| anyhow!("open branch metadata reader: {e:?}"))?;
        let branch_meta: TribleSet = branch_reader
            .get(branch_meta_handle)
            .map_err(|e| anyhow!("load archive branch metadata: {e:?}"))?;
        let source_head = find!(
            (head: Inline<Handle<SimpleArchive>>),
            pattern!(&branch_meta, [{ _?branch @ triblespace::core::repo::head: ?head }])
        )
        .at_most_one()
        .map_err(|_| anyhow!("archive branch metadata has ambiguous source HEADs"))?
        .map(|(head,)| head);

        // Parse and validate both coverage certificates before touching any
        // segment blob. A stale manifest may contain obsolete or missing
        // handles; the useful diagnostic is the uncovered source gap.
        let content_attr = common::archive::content.id();
        let index_attach_start = Instant::now();
        let reader = repo
            .storage_mut()
            .reader()
            .map_err(|e| anyhow!("open pile reader: {e:?}"))?;
        let kind = Bm25Rollup::new(reader, content_attr);
        let bm25_kind = kind.kind_id();
        let bm25_manifest = Manifest::from_tribles(&branch_meta, bm25_kind);
        if !bm25_manifest.covers_head(source_head) {
            bail!(
                "BM25 index {bm25_kind:x} is stale at {:?}, source HEAD is {:?}; run `archive index`",
                bm25_manifest.covered,
                source_head
            );
        }

        let succinct_kind = SuccinctRollup::new();
        let succinct_manifest = Manifest::from_tribles(&branch_meta, succinct_kind.kind_id());
        if !succinct_manifest.covers_head(source_head) {
            bail!(
                "Succinct index {} is stale at {:?}, source HEAD is {:?}; run `archive index`",
                SuccinctRollup::KIND_ID_HEX,
                succinct_manifest.covered,
                source_head
            );
        }
        if bm25_manifest.segments.is_empty() {
            bail!(
                "no BM25 search segments on this pile yet — run `archive index` \
                 first, or use --exact for a substring scan"
            );
        }
        if succinct_manifest.segments.is_empty() {
            bail!("no Succinct archive segments on this pile yet — run `archive index`");
        }

        // 1. Attach only the BM25 handles from the validated snapshot.
        let segments = {
            let mut home = IndexHome::new(repo.storage_mut(), branch_id, kind);
            home.attach_manifest(&bm25_manifest)
                .map_err(|e| anyhow!("attach BM25 segments: {e}"))?
        };
        tracing::info!(
            segments = segments.len(),
            elapsed_ms = index_attach_start.elapsed().as_millis() as u64,
            "BM25 manifest and segments attached"
        );

        // 2. Rank across the segment union (per-segment BM25; best score wins).
        let bm25_start = Instant::now();
        let ranked = query_across(&segments, &hash_tokens(&text));
        let total_docs: usize = segments.iter().map(|s| s.doc_count()).sum();
        tracing::info!(
            segment_documents = total_docs,
            hits = ranked.len(),
            elapsed_ms = bm25_start.elapsed().as_millis() as u64,
            "BM25 query complete"
        );
        drop(segments);

        if limit == 0 || ranked.is_empty() {
            tracing::info!(
                materialized = 0,
                elapsed_ms = 0,
                "search results materialized"
            );
            return Ok(());
        }

        // 3. Only a query with results to materialise needs the Succinct LSM.
        let succinct_attach_start = Instant::now();
        let succinct_segments = {
            let mut home = IndexHome::new(repo.storage_mut(), branch_id, succinct_kind);
            home.attach_manifest(&succinct_manifest)
                .map_err(|e| anyhow!("attach Succinct segments: {e}"))?
        };
        tracing::info!(
            segments = succinct_segments.len(),
            elapsed_ms = succinct_attach_start.elapsed().as_millis() as u64,
            "Succinct manifest and segments attached"
        );
        let succinct = SuccinctRollup::union(&succinct_segments);
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull workspace for blob reads: {e:?}"))?;

        let materialize_start = Instant::now();
        let mut materialized = 0usize;
        for (doc, score) in ranked.into_iter().take(limit) {
            let Ok(message_id): Result<Id, _> = doc.try_from_inline() else {
                continue;
            };
            let Some((author_id, content_handle, created_at)) = find!(
                (
                    author: Id,
                    content: Inline<Handle<LongString>>,
                    created_at: Inline<NsTAIInterval>
                ),
                pattern!(&succinct, [{
                    message_id @
                        common::archive::author: ?author,
                        common::archive::content: ?content,
                        common::metadata::created_at: ?created_at,
                }])
            )
            .next() else {
                continue;
            };
            let content = load_longstring(&mut ws, content_handle)?;
            let name = author_name_from_index(&mut ws, &succinct, author_id)?;
            let role = author_role_from_index(&mut ws, &succinct, author_id)?;
            let (lower, _upper): (Epoch, Epoch) = created_at.try_from_inline().unwrap();
            let role = role.as_deref().unwrap_or("");
            println!(
                "{score:7.2} {} {} {} {}",
                &format!("{message_id:x}")[..8],
                lower,
                if role.is_empty() {
                    name
                } else {
                    format!("{name} ({role})")
                },
                snippet(&content, 120)
            );
            materialized += 1;
        }
        tracing::info!(
            materialized,
            elapsed_ms = materialize_start.elapsed().as_millis() as u64,
            "search results materialized"
        );
        Ok(())
    })();

    let close_start = Instant::now();
    let close_result = repo
        .close()
        .map_err(|e| anyhow!("close pile {}: {e:?}", pile_path.display()));
    tracing::info!(
        elapsed_ms = close_start.elapsed().as_millis() as u64,
        "search repository close complete"
    );
    match (res, close_result) {
        (Err(err), _) => Err(err),
        (Ok(()), Err(err)) => Err(err),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// Substring / case-sensitive scan fallback — inherently a full-content
/// pass, so it still checks out the branch. Slow at archive scale but
/// needs no index.
fn exact_scan(
    repo: &mut common::Repo,
    branch_id: Id,
    text: &str,
    limit: usize,
    case_sensitive: bool,
) -> Result<()> {
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
    let catalog = ws.checkout(..).context("checkout workspace")?;

    let needle = if case_sensitive {
        text.to_string()
    } else {
        text.to_lowercase()
    };

    let mut matches = Vec::new();
    for (message_id, author_id, content_handle, created_at) in find!(
        (
            message: Id,
            author: Id,
            content: Inline<Handle<LongString>>,
            created_at: Inline<NsTAIInterval>
        ),
        pattern!(&catalog, [{
            ?message @
                common::metadata::tag: common::archive::kind_message,
                common::archive::author: ?author,
                common::archive::content: ?content,
                common::metadata::created_at: ?created_at,
        }])
    ) {
        let content = load_longstring(&mut ws, content_handle)?;
        let haystack = if case_sensitive {
            content.clone()
        } else {
            content.to_lowercase()
        };
        if haystack.contains(&needle) {
            matches.push((interval_key(created_at), message_id, author_id, created_at, content));
        }
    }
    matches.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    for (_key, message_id, author_id, created_at, content) in matches.into_iter().rev().take(limit) {
        let name = author_name(&mut ws, &catalog, author_id)?;
        let role = author_role(&mut ws, &catalog, author_id)?;
        let (lower, _upper): (Epoch, Epoch) = created_at.try_from_inline().unwrap();
        let role = role.as_deref().unwrap_or("");
        println!(
            "{} {} {} {}",
            &format!("{message_id:x}")[..8],
            lower,
            if role.is_empty() {
                name
            } else {
                format!("{name} ({role})")
            },
            snippet(&content, 120)
        );
    }
    Ok(())
}

fn remove_legacy_rollup(set: &mut TribleSet) -> bool {
    let mut old = TribleSet::new();
    for trible in set
        .iter()
        .filter(|trible| *trible.a() == triblespace::core::repo::rollup.id())
    {
        old.insert(trible);
    }
    if old.is_empty() {
        return false;
    }
    *set = set.difference(&old);
    true
}

fn advance_coverage_frontier(
    ws: &mut common::Ws,
    frontier: &mut Vec<common::CommitHandle>,
    commit: common::CommitHandle,
) -> Result<()> {
    let meta: TribleSet = ws
        .get(commit)
        .map_err(|err| anyhow!("load commit metadata {commit:?}: {err:?}"))?;
    let parents: HashSet<[u8; 32]> = find!(
        (parent: Inline<Handle<SimpleArchive>>),
        pattern!(&meta, [{ triblespace::core::repo::parent: ?parent }])
    )
    .map(|(parent,)| parent.raw)
    .collect();
    frontier.retain(|tip| !parents.contains(&tip.raw));
    frontier.push(commit);
    frontier.sort_unstable_by_key(|tip| tip.raw);
    frontier.dedup_by_key(|tip| tip.raw);
    Ok(())
}

/// Build or repair the archive's two derived indexes by replaying source
/// commits, never by checking out their union. Every source commit is one
/// logical LSM leaf; large commit payloads are physically sharded under one
/// atomic coverage advance. The frontier is checkpointed after each commit,
/// making interruption and rerun idempotent.
fn run_index_standalone(pile_path: &Path, branch_id: Id, branch_name: &str) -> Result<()> {
    // Standalone repair publishes index checkpoints directly rather than
    // pushing a workspace, so an on-commit hook is unnecessary. Own exactly
    // one rollup for this indexing lifecycle.
    let mut repo = common::open_repo(pile_path)?;
    let res = (|| -> Result<()> {
        common::validate_branch_for_read(&mut repo, branch_id, branch_name)?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
        let target_head = ws
            .head()
            .ok_or_else(|| anyhow!("archive branch has no commits to index"))?;

        let mut branch_meta_handle = repo
            .storage_mut()
            .head(branch_id)
            .map_err(|err| anyhow!("read archive branch head: {err:?}"))?
            .ok_or_else(|| anyhow!("archive branch is missing"))?;
        let branch_reader = repo
            .storage_mut()
            .reader()
            .map_err(|err| anyhow!("open branch reader: {err:?}"))?;
        let mut branch_meta: TribleSet = branch_reader
            .get(branch_meta_handle)
            .map_err(|err| anyhow!("load archive branch metadata: {err:?}"))?;

        // Manifest compatibility and readability do not need a GPU backend.
        // Accelerated and CPU Succinct rollups deliberately share kind id and
        // canonical segment bytes.
        let succinct_format = SuccinctRollup::new();
        let bm25_reader = repo
            .storage_mut()
            .reader()
            .map_err(|err| anyhow!("open BM25 reader: {err:?}"))?;
        let bm25 = Bm25Rollup::new(bm25_reader, common::archive::content.id());
        let succinct_manifest = Manifest::from_tribles(&branch_meta, succinct_format.kind_id());
        let bm25_manifest = Manifest::from_tribles(&branch_meta, bm25.kind_id());

        let reachable = ancestors(target_head)
            .select(&mut ws)
            .context("walk archive commit DAG")?;
        let same_frontier = succinct_manifest.covered == bm25_manifest.covered;
        let frontier_is_reachable = succinct_manifest
            .covered
            .iter()
            .all(|tip| reachable.get(&tip.raw).is_some());
        // A pre-coverage manifest may already contain whole-corpus or
        // repeatedly appended legacy segments. Empty coverage cannot certify
        // those segments, so replaying on top would duplicate the corpus and
        // then falsely bless it as current. Only a genuinely empty forest may
        // bootstrap from an empty frontier.
        let has_uncertified_segments = succinct_manifest.covered.is_empty()
            && (!succinct_manifest.segments.is_empty() || !bm25_manifest.segments.is_empty());
        let candidate_resume = same_frontier && frontier_is_reachable && !has_uncertified_segments;
        let manifests_readable = if candidate_resume {
            let succinct_result = {
                let mut home = IndexHome::new(repo.storage_mut(), branch_id, succinct_format);
                home.attach_manifest(&succinct_manifest)
            };
            let bm25_result = {
                let mut home = IndexHome::new(repo.storage_mut(), branch_id, bm25.clone());
                home.attach_manifest(&bm25_manifest)
            };
            match (succinct_result, bm25_result) {
                (Ok(_), Ok(_)) => true,
                (succinct_result, bm25_result) => {
                    eprintln!(
                        "discarding unreadable archive index manifests (Succinct: {}; BM25: {})",
                        succinct_result
                            .err()
                            .map_or_else(|| "ok".to_owned(), |err| err.to_string()),
                        bm25_result
                            .err()
                            .map_or_else(|| "ok".to_owned(), |err| err.to_string()),
                    );
                    false
                }
            }
        } else {
            true
        };
        let resume = candidate_resume && manifests_readable;

        let mut frontier = if resume {
            succinct_manifest.covered.clone()
        } else {
            clear_manifest(&mut branch_meta, succinct_format.kind_id());
            clear_manifest(&mut branch_meta, bm25.kind_id());
            Vec::new()
        };
        let removed_legacy = remove_legacy_rollup(&mut branch_meta);

        let commits = if frontier.as_slice() == [target_head] {
            Vec::new()
        } else if frontier.is_empty() {
            commits_topological(&mut ws, reachable.clone()).context("order archive commits")?
        } else {
            commits_topological(
                &mut ws,
                difference(reachable.clone(), ancestors(frontier.clone())),
            )
            .context("order uncovered archive commits")?
        };

        if commits.is_empty() && !removed_legacy && resume {
            println!("archive indexes already cover HEAD ({target_head:?})");
            return Ok(());
        }

        eprintln!(
            "indexing {} uncovered commit(s) as logical LSM leaves…",
            commits.len()
        );
        let succinct = common::archive_succinct_rollup();
        for (i, commit) in commits.iter().copied().enumerate() {
            if i == 0 {
                eprintln!("  starting commit 1/{} ({commit:?})", commits.len());
            }
            let commit_started = Instant::now();
            common::index_archive_commit(
                repo.storage_mut(),
                commit,
                &succinct,
                &bm25,
                &mut branch_meta,
            )?;
            advance_coverage_frontier(&mut ws, &mut frontier, commit)?;
            set_coverage(
                &mut branch_meta,
                succinct_format.kind_id(),
                frontier.clone(),
            );
            set_coverage(&mut branch_meta, bm25.kind_id(), frontier.clone());

            let new_meta: Inline<Handle<SimpleArchive>> = repo
                .storage_mut()
                .put(branch_meta.clone())
                .map_err(|err| anyhow!("store index checkpoint: {err:?}"))?;
            match repo
                .storage_mut()
                .update(branch_id, Some(branch_meta_handle), Some(new_meta))
                .map_err(|err| anyhow!("publish index checkpoint: {err:?}"))?
            {
                PushResult::Success() => branch_meta_handle = new_meta,
                PushResult::Conflict(_) => {
                    bail!("archive branch changed during indexing; rerun to resume from coverage")
                }
            }
            let commit_elapsed = commit_started.elapsed();
            if commit_elapsed.as_secs() >= 5 {
                eprintln!(
                    "  …{}/{} commit {commit:?} indexed and checkpointed in {:.1?}",
                    i + 1,
                    commits.len(),
                    commit_elapsed,
                );
            } else if (i + 1) % 100 == 0 || i + 1 == commits.len() {
                eprintln!("  …{}/{} commits indexed", i + 1, commits.len());
            }
        }

        // A migration that only removed the legacy monolith still needs one
        // metadata CAS even when coverage was already current.
        if commits.is_empty() && removed_legacy {
            let new_meta: Inline<Handle<SimpleArchive>> = repo
                .storage_mut()
                .put(branch_meta.clone())
                .map_err(|err| anyhow!("store migrated index metadata: {err:?}"))?;
            match repo
                .storage_mut()
                .update(branch_id, Some(branch_meta_handle), Some(new_meta))
                .map_err(|err| anyhow!("publish migrated index metadata: {err:?}"))?
            {
                PushResult::Success() => {}
                PushResult::Conflict(_) => {
                    bail!("archive branch changed during index migration; rerun")
                }
            }
        }

        if frontier.as_slice() != [target_head] {
            bail!(
                "index traversal ended at frontier {:?}, expected {:?}",
                frontier,
                target_head
            );
        }
        println!("archive Succinct and BM25 indexes now cover HEAD");
        Ok(())
    })();

    let close_result = repo
        .close()
        .map_err(|e| anyhow!("close pile {}: {e:?}", pile_path.display()));
    match (res, close_result) {
        (Err(err), _) => Err(err),
        (Ok(()), Err(err)) => Err(err),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.trace, cli.trace_filter.as_deref());
    let pile_path = cli.pile.clone();
    let Some(cmd) = cli.command else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };

    // Search owns one repository for its whole read path. Opening a fresh
    // `Pile` rebuilds its in-memory record index, so resolving the branch in
    // a throwaway repository and reopening for the query doubles cold-start
    // work on archive-scale piles.
    if let Command::Search {
        text,
        limit,
        case_sensitive,
        exact,
    } = &cmd
    {
        let search_open_start = Instant::now();
        let mut repo = common::open_repo(&pile_path)?;
        tracing::info!(
            elapsed_ms = search_open_start.elapsed().as_millis() as u64,
            "search repository open complete"
        );

        let branch_resolution_start = Instant::now();
        let branch_id = if let Some(hex) = cli.branch_id.as_deref() {
            Id::from_hex(hex.trim()).ok_or_else(|| anyhow!("invalid branch id '{hex}'"))?
        } else {
            repo.ensure_branch(&cli.branch, None)
                .map_err(|e| anyhow!("ensure archive branch: {e:?}"))?
        };
        common::validate_branch_for_read(&mut repo, branch_id, &cli.branch)?;
        tracing::info!(
            elapsed_ms = branch_resolution_start.elapsed().as_millis() as u64,
            "search branch resolution complete"
        );

        return run_search_standalone(
            repo,
            &pile_path,
            branch_id,
            text.clone(),
            *limit,
            *case_sensitive,
            *exact,
        );
    }

    let branch_resolution_start = Instant::now();
    let branch_id = common::with_repo(&pile_path, |repo| {
        if let Some(hex) = cli.branch_id.as_deref() {
            return Id::from_hex(hex.trim())
                .ok_or_else(|| anyhow!("invalid branch id '{hex}'"));
        }
        repo.ensure_branch(&cli.branch, None)
            .map_err(|e| anyhow!("ensure archive branch: {e:?}"))
    })?;
    tracing::info!(
        elapsed_ms = branch_resolution_start.elapsed().as_millis() as u64,
        "command branch resolution complete"
    );
    if let Command::Import { source, path } = cmd {
        return run_import_jobs(source, path.as_deref(), &pile_path, &cli.branch, branch_id);
    }
    if let Command::Replay {
        action,
        limit,
        with_tools,
        persona,
    } = cmd
    {
        return run_replay_standalone(
            &pile_path,
            branch_id,
            &cli.branch,
            &action,
            limit,
            with_tools,
            persona.as_deref(),
        );
    }
    if let Command::Index = cmd {
        return run_index_standalone(&pile_path, branch_id, &cli.branch);
    }

    let (mut repo, branch_id) = common::open_repo_for_read(&pile_path, branch_id, &cli.branch)?;

    let res = (|| -> Result<()> {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
        let catalog = ws.checkout(..).context("checkout workspace")?;

        match cmd {
            Command::Import { .. } => unreachable!("import is handled before opening the branch"),
            Command::List { limit } => {
                let mut records = Vec::new();
                for (message_id, author_id, content_handle, created_at) in find!(
                    (
                        message: Id,
                        author: Id,
                        content: Inline<Handle<LongString>>,
                        created_at: Inline<NsTAIInterval>
                    ),
                    pattern!(&catalog, [{
                        ?message @
                            common::metadata::tag: common::archive::kind_message,
                            common::archive::author: ?author,
                            common::archive::content: ?content,
                            common::metadata::created_at: ?created_at,
                    }])
                ) {
                    records.push((
                        interval_key(created_at),
                        message_id,
                        author_id,
                        content_handle,
                        created_at,
                    ));
                }
                records.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
                let take = limit.min(records.len());
                for (_key, message_id, author_id, content_handle, created_at) in
                    records.into_iter().rev().take(take)
                {
                    let name = author_name(&mut ws, &catalog, author_id)?;
                    let role = author_role(&mut ws, &catalog, author_id)?;
                    let content = load_longstring(&mut ws, content_handle)?;
                    let (lower, _upper): (Epoch, Epoch) = created_at.try_from_inline().unwrap();
                    let role = role.as_deref().unwrap_or("");
                    println!(
                        "{} {} {} {}",
                        &format!("{message_id:x}")[..8],
                        lower,
                        if role.is_empty() {
                            name
                        } else {
                            format!("{name} ({role})")
                        },
                        snippet(&content, 120)
                    );
                }
            }
            Command::Show { id } => {
                let message_id = resolve_message_id(&catalog, &id)?;
                let (message_id, name, role, created_at, content_handle, reply_to) =
                    message_record(&mut ws, &catalog, message_id)?;
                let content = load_longstring(&mut ws, content_handle)?;
                let (lower, _upper): (Epoch, Epoch) = created_at.try_from_inline().unwrap();
                let content_type = message_content_type(&catalog, message_id);
                let attachments = message_attachments(&mut ws, &catalog, message_id)?;

                println!("id: {message_id:x}");
                println!("created_at: {lower}");
                match role {
                    Some(role) => println!("author: {name} ({role})"),
                    None => println!("author: {name}"),
                }
                if let Some(parent) = reply_to {
                    println!("reply_to: {parent:x}");
                }
                if let Some(content_type) = content_type {
                    println!("content_type: {content_type}");
                }
                if !attachments.is_empty() {
                    println!("attachments: {}", attachments.len());
                    for att in attachments {
                        let mut extras = Vec::new();
                        if let Some(mime) = att.mime.as_deref() {
                            extras.push(mime.to_string());
                        }
                        if let Some(size) = att.size_bytes {
                            extras.push(format!("{size}b"));
                        }
                        if let (Some(w), Some(h)) = (att.width_px, att.height_px) {
                            extras.push(format!("{w}x{h}px"));
                        }
                        if att.has_data {
                            extras.push("data".to_string());
                        }
                        let label = att
                            .name
                            .as_deref()
                            .or(att.source_id.as_deref())
                            .unwrap_or("<unknown>");
                        if extras.is_empty() {
                            println!("  - {} {}", &format!("{:x}", att.id)[..8], label);
                        } else {
                            println!(
                                "  - {} {} ({})",
                                &format!("{:x}", att.id)[..8],
                                label,
                                extras.join(", ")
                            );
                        }
                    }
                }
                println!();
                print!("{content}");
                if !content.ends_with('\n') {
                    println!();
                }
            }
            Command::Thread { id, limit } => {
                let leaf = resolve_message_id(&catalog, &id)?;
                let mut chain = Vec::new();
                let mut seen = HashSet::new();
                let mut current = leaf;

                for _ in 0..limit {
                    if !seen.insert(current) {
                        break;
                    }
                    chain.push(current);
                    let parent = find!(
                        (parent: Id),
                        pattern!(&catalog, [{ current @ common::archive::reply_to: ?parent }])
                    )
                    .into_iter()
                    .next()
                    .map(|(p,)| p);
                    let Some(parent) = parent else { break };
                    current = parent;
                }

                chain.reverse();
                for message_id in chain {
                    let (message_id, name, role, created_at, content_handle, _reply_to) =
                        message_record(&mut ws, &catalog, message_id)?;
                    let content = load_longstring(&mut ws, content_handle)?;
                    let (lower, _upper): (Epoch, Epoch) = created_at.try_from_inline().unwrap();
                    let role = role.as_deref().unwrap_or("");
                    println!(
                        "{} {} {} {}",
                        &format!("{message_id:x}")[..8],
                        lower,
                        if role.is_empty() {
                            name
                        } else {
                            format!("{name} ({role})")
                        },
                        snippet(&content, 120)
                    );
                }
            }
            Command::Search { .. } => {
                unreachable!("search is handled before opening the branch")
            }
            Command::Index => {
                unreachable!("index is handled before opening the branch")
            }
            Command::Imports { format, limit } => {
                let format_filter = format.map(|s| s.to_lowercase());

                let mut conversations = Vec::new();
                for (conversation_id, source_format, source_conversation_id_handle) in find!(
                    (
                        conversation: Id,
                        format: String,
                        source_conversation_id: Inline<Handle<LongString>>
                    ),
                    pattern!(&catalog, [{
                        ?conversation @
                            common::metadata::tag: common::import_schema::kind_conversation,
                            common::import_schema::source_format: ?format,
                            common::import_schema::source_conversation_id: ?source_conversation_id,
                    }])
                ) {
                    if let Some(filter) = format_filter.as_deref() {
                        if source_format.to_lowercase() != filter {
                            continue;
                        }
                    }
                    let source_conversation_id =
                        load_longstring(&mut ws, source_conversation_id_handle)?;
                    conversations.push((conversation_id, source_format, source_conversation_id));
                }

                conversations.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(&b.0)));
                for (conversation_id, source_format, source_conversation_id) in
                    conversations.into_iter().take(limit)
                {
                    println!(
                        "{} {} convo={}",
                        &format!("{conversation_id:x}")[..8],
                        source_format,
                        source_conversation_id
                    );
                }
            }
            Command::Replay { .. } => {
                unreachable!("replay is handled before opening the archive branch")
            }
        }

        Ok(())
    })();

    let close_result = repo
        .close()
        .map_err(|e| anyhow!("close pile {}: {e:?}", pile_path.display()));

    match (res, close_result) {
        (Err(err), _) => Err(err),
        (Ok(()), Err(err)) => Err(err),
        (Ok(()), Ok(())) => Ok(()),
    }
}
