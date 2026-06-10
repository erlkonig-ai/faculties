
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use hifitime::Epoch;
use tracing::info_span;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval, U256BE};
use triblespace::prelude::*;

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
mod common {
    #![allow(dead_code)]

    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result, anyhow};
    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use rand_core::OsRng;
    use rayon::ThreadPoolBuilder;
    use rayon::prelude::*;
    
    use tracing::info_span;
    use triblespace::core::id::ExclusiveId;
    pub use triblespace::core::metadata;
    use triblespace::core::repo::pile::Pile;
    use triblespace::core::repo::{Repository, Workspace};
    use triblespace::prelude::blobencodings::{LongString, SimpleArchive};
    use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval};
    use triblespace::prelude::*;

    pub use faculties::schemas::archive::{self as archive_schema, archive, import_schema};

    pub type Repo = Repository<Pile>;
    pub type Ws = Workspace<Pile>;
    pub type CommitHandle = Inline<Handle<SimpleArchive>>;

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
        let mut pile =
            Pile::open(pile_path).map_err(|e| anyhow!("open pile: {e:?}"))?;
        if let Err(err) = pile.restore() {
            let _ = pile.close();
            return Err(anyhow!("restore pile: {err:?}"));
        }
        let signing_key = SigningKey::generate(&mut OsRng);
        let repo = Repository::new(pile, signing_key, TribleSet::new())
            .map_err(|err| anyhow!("create repository: {err:?}"))?;
        Ok((repo, branch_id))
    }

    pub fn open_repo_for_read(
        pile_path: &Path,
        branch_id: Id,
        branch_name: &str,
    ) -> Result<(Repo, Id)> {
        let mut repo = open_repo(pile_path)?;
        let res = (|| -> Result<(), anyhow::Error> {
            if repo
                .storage_mut()
                .head(branch_id)
                .map_err(|e| anyhow!("branch head {branch_name}: {e:?}"))?
                .is_none()
            {
                return Err(anyhow!("unknown branch {branch_name} ({branch_id:x})"));
            }
            Ok(())
        })();
        if let Err(err) = res {
            let _ = repo.close();
            return Err(err);
        }
        Ok((repo, branch_id))
    }

    fn open_repo(pile_path: &Path) -> Result<Repo> {
        let mut pile = Pile::open(pile_path).map_err(|e| anyhow!("open pile: {e:?}"))?;
        if let Err(err) = pile.restore() {
            // Avoid Drop warnings on early errors.
            let _ = pile.close();
            return Err(anyhow!("restore pile: {err:?}"));
        }
        let signing_key = SigningKey::generate(&mut OsRng);
        Repository::new(pile, signing_key, TribleSet::new())
            .map_err(|err| anyhow!("create repository: {err:?}"))
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

#[derive(Parser)]
#[command(name = "archive", about = "Query imported archives in TribleSpace")]
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
    /// Enable tracing spans for importer profiling.
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
    /// Search message content (substring match).
    Search {
        #[arg(help = "Substring to search for. Use @path for file input or @- for stdin.")]
        text: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Use case-sensitive matching.
        #[arg(long)]
        case_sensitive: bool,
    },
    /// List imported conversations.
    Imports {
        format: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ImportSource {
    Chatgpt,
    Codex,
    Copilot,
    Gemini,
    ClaudeCode,
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

    let branch_id = common::with_repo(&pile_path, |repo| {
        if let Some(hex) = cli.branch_id.as_deref() {
            return Id::from_hex(hex.trim())
                .ok_or_else(|| anyhow!("invalid branch id '{hex}'"));
        }
        repo.ensure_branch(&cli.branch, None)
            .map_err(|e| anyhow!("ensure archive branch: {e:?}"))
    })?;
    if let Command::Import { source, path } = cmd {
        return run_import_jobs(source, path.as_deref(), &pile_path, &cli.branch, branch_id);
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
            Command::Search {
                text,
                limit,
                case_sensitive,
            } => {
                let text = load_value_or_file(&text, "search text")?;
                let needle = if case_sensitive {
                    text
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
                        matches.push((
                            interval_key(created_at),
                            message_id,
                            author_id,
                            created_at,
                            content,
                        ));
                    }
                }
                matches.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
                for (_key, message_id, author_id, created_at, content) in
                    matches.into_iter().rev().take(limit)
                {
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
