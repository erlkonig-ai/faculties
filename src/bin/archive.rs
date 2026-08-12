use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Once;

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::archive_claude_code::{self, ProjectionSummary};
use faculties::archive_collection::{
    self as archive_collection, ArchiveImportWriter, ArchivePart, ArchivePayload,
    ArchiveProjection, ArchiveSearchSnapshot, ArchiveSnapshot,
};
use faculties::archive_cutover;
use faculties::blockdag::CatalogValidation;
use faculties::collection_cutover::{freeze_source, load_signer, open_pile_strict};
use faculties::comb::{
    self as comb_model, CombCatalog, CursorDraft, CursorResolution, CursorState,
};
use faculties::comb_cutover;
use faculties::schemas::blockdag as archive_schema;
use faculties::schemas::memory::DEFAULT_COMB_SCOPE_ID;
use hifitime::Epoch;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;
use triblespace::core::collection::Collection;
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::time::NsTAIInterval;
use triblespace::core::inline::{Inline, TryToInline};
use triblespace::core::trible::{Fragment, TribleSet};
use triblespace::macros::{find, pattern};

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "archive",
    about = "Import and query the canonical Archive block DAG"
)]
struct Cli {
    /// Path to the pile file to use.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Enable tracing spans for projection and collection derivation.
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
    /// Project one Claude Code JSONL file or directory and publish one COMMIT.
    Import {
        /// JSONL file or recursively scanned directory.
        path: PathBuf,
    },
    /// List the most recent source projections from one frozen Archive view.
    List {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Show one exact source projection by id prefix.
    Show { id: String },
    /// Show the complete canonical ancestor DAG of one source projection.
    Thread {
        id: String,
        /// Maximum accepted block count. Exceeding it is an error rather than
        /// silently hiding one fork.
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Search canonical block text through an exact portable BM25 cover.
    Search {
        #[arg(help = "Query text. Use @path for file input or @- for stdin.")]
        text: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Ensure exact raw-Succinct and portable BM25 collection derives.
    Index,
    /// Migrate stopped legacy Archive and optional Comb repository branches.
    MigrateLegacy,
    /// Replay canonical blocks as one interleaved temporal stream.
    Replay {
        /// `start <from-ts>`, `stop`, or nothing for the next batch.
        #[arg(value_name = "ACTION")]
        action: Vec<String>,
        /// Blocks per batch. An equal-timestamp run is never split.
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Include tool, thinking, event, and media-only blocks.
        #[arg(long)]
        with_tools: bool,
        /// Cursor owner. There is deliberately no default persona.
        #[arg(long, env = "PERSONA")]
        persona: Option<String>,
    },
}

#[derive(Clone, Copy)]
struct ArchiveStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

struct ReplayView {
    archive: ArchiveSnapshot,
    comb_facts: TribleSet,
    comb_catalog: CombCatalog,
}

impl ArchiveStorage<'_> {
    fn load(&self) -> Result<ArchiveSnapshot> {
        ArchiveSnapshot::load_local(self.pile, self.key, archive_schema::DEFAULT_SCOPE_ID)
    }

    fn load_comb(&self) -> Result<(TribleSet, CombCatalog)> {
        let signer = load_signer(self.pile, self.key)?;
        let pile = open_pile_strict(self.pile)?;
        let mut collection = Collection::new(pile, DEFAULT_COMB_SCOPE_ID, signer);
        let result = (|| {
            let facts = collection
                .materialize()
                .context("materialize Comb cursor collection")?;
            let catalog =
                comb_model::load_catalog(&facts).context("validate Comb cursor collection")?;
            Ok((facts, catalog))
        })();
        finish_collection(collection, result)
    }

    /// Materialize the Archive and its separate Comb cursor collection from
    /// consecutive known-prefix views. Cursor publication rematerializes Comb
    /// and validates the successor again at the commit boundary.
    fn load_replay(&self) -> Result<ReplayView> {
        let archive = self.load()?;
        let (comb_facts, comb_catalog) = self.load_comb()?;
        Ok(ReplayView {
            archive,
            comb_facts,
            comb_catalog,
        })
    }
}

fn finish_collection<T>(
    collection: Collection<triblespace::core::repo::pile::Pile>,
    result: Result<T>,
) -> Result<T> {
    let close = collection.into_storage().close();
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(close_error)) => Err(anyhow!("close Archive pile: {close_error}")),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Archive pile after failure also failed: {close_error}"
        ))),
    }
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
    });
}

fn run_import(storage: ArchiveStorage<'_>, path: &Path) -> Result<()> {
    let mut writer = ArchiveImportWriter::open(storage.pile, storage.key)?;
    let projection = archive_claude_code::project_path(path, |projected| {
        writer
            .stage_fragment(projected.fragment)
            .with_context(|| format!("stage {}", projected.source_path.display()))
    });
    let (summary, commit) = writer.finish(projection)?;
    print_import_summary(&summary, commit.is_some());
    Ok(())
}

fn print_import_summary(summary: &ProjectionSummary, published: bool) {
    println!(
        "projected {} file(s), emitted {} fragment(s), {} source projection(s), {} content part(s)",
        summary.files_scanned,
        summary.fragments_emitted,
        summary.stats.source_projections,
        summary.stats.content_parts,
    );
    println!(
        "skipped={} missing_identity={} skipped_parents={} unresolved_parents={} unresolved_tool_results={} undecodable_images={}",
        summary.stats.skipped_records,
        summary.stats.missing_source_identity,
        summary.stats.skipped_parents,
        summary.stats.unresolved_parents,
        summary.stats.unresolved_tool_results,
        summary.stats.undecodable_images,
    );
    println!(
        "Archive collection: {}",
        if published {
            "one signed COMMIT published"
        } else {
            "unchanged (projector emitted no facts)"
        }
    );
}

fn short_id(id: Id) -> String {
    format!("{id:X}").chars().take(8).collect()
}

fn snippet(text: &str, max: usize) -> String {
    let mut out = String::new();
    for (count, ch) in text.chars().enumerate() {
        if count == max {
            out.push_str("...");
            break;
        }
        out.push(if ch == '\n' || ch == '\r' { ' ' } else { ch });
    }
    out
}

fn interval_bounds(interval: Inline<NsTAIInterval>) -> Result<(Epoch, Epoch)> {
    interval
        .try_from_inline()
        .map_err(|error| anyhow!("decode Archive timestamp: {error:?}"))
}

fn interval_key(interval: Inline<NsTAIInterval>) -> Result<i128> {
    let (lower, _upper): (i128, i128) = interval
        .try_from_inline()
        .map_err(|error| anyhow!("decode Archive timestamp: {error:?}"))?;
    Ok(lower)
}

fn format_interval(interval: Option<Inline<NsTAIInterval>>) -> Result<String> {
    let Some(interval) = interval else {
        return Ok("<untimed>".to_owned());
    };
    let (lower, upper) = interval_bounds(interval)?;
    if lower == upper {
        Ok(lower.to_string())
    } else {
        Ok(format!("{lower}..{upper}"))
    }
}

fn modality_label(id: Id) -> String {
    match id {
        archive_schema::content_fact::modality::TEXT => "text".to_owned(),
        archive_schema::content_fact::modality::AUDIO => "audio".to_owned(),
        archive_schema::content_fact::modality::IMAGE => "image".to_owned(),
        archive_schema::content_fact::modality::TOOL_CALL => "tool-call".to_owned(),
        archive_schema::content_fact::modality::TOOL_RESULT => "tool-result".to_owned(),
        archive_schema::content_fact::modality::THINKING => "thinking".to_owned(),
        archive_schema::content_fact::modality::EVENT => "event".to_owned(),
        _ => format!("modality:{id:X}"),
    }
}

fn direction_label(id: Id) -> String {
    match id {
        archive_schema::content_fact::direction::IN => "in".to_owned(),
        archive_schema::content_fact::direction::OUT => "out".to_owned(),
        archive_schema::content_fact::direction::AMBIENT => "ambient".to_owned(),
        _ => format!("direction:{id:X}"),
    }
}

fn payload_summary(payload: &ArchivePayload) -> String {
    match payload {
        ArchivePayload::Text(text) => snippet(text, 120),
        ArchivePayload::Resident { blob, media_type } => format!(
            "[resident {} bytes {}]",
            short_id(*media_type),
            hex::encode_upper(blob.raw),
        ),
        ArchivePayload::External {
            pointer,
            namespace,
            media_type,
            size,
            resolutions,
        } => format!(
            "[external {} namespace={} media={} size={} resolutions={}]",
            pointer,
            short_id(*namespace),
            media_type.map(short_id).unwrap_or_else(|| "?".to_owned()),
            size.map(|value| value.to_string())
                .unwrap_or_else(|| "?".to_owned()),
            resolutions.len(),
        ),
    }
}

fn projection_snippet(projection: &ArchiveProjection) -> String {
    let joined = projection
        .parts
        .iter()
        .map(|part| payload_summary(&part.payload))
        .collect::<Vec<_>>()
        .join(" ");
    snippet(&joined, 120)
}

fn projection_actor(projection: &ArchiveProjection) -> String {
    let mut values = Vec::new();
    if let Some(author) = &projection.raw_author {
        values.push(author.clone());
    }
    if let Some(role) = &projection.raw_role {
        values.push(role.clone());
    }
    if let Some(model) = &projection.raw_model {
        values.push(model.clone());
    }
    if values.is_empty() {
        "<unattributed>".to_owned()
    } else {
        values.join("/")
    }
}

fn render_projection_summary(projection: &ArchiveProjection) -> Result<String> {
    Ok(format!(
        "{} {} {} {}",
        short_id(projection.id),
        format_interval(projection.block_timestamp)?,
        projection_actor(projection),
        projection_snippet(projection),
    ))
}

fn render_part(out: &mut String, part: &ArchivePart) -> Result<()> {
    writeln!(
        out,
        "part[{}]: {} {} id={:X} fact={:X}",
        part.ordinal,
        modality_label(part.modality),
        direction_label(part.direction),
        part.id,
        part.fact,
    )?;
    if let Some(target) = part.responds_to {
        writeln!(out, "  responds_to: {target:X}")?;
    }
    match &part.payload {
        ArchivePayload::Text(text) => {
            writeln!(out, "  text:")?;
            for line in text.lines() {
                writeln!(out, "    {line}")?;
            }
        }
        ArchivePayload::Resident { blob, media_type } => {
            writeln!(out, "  resident_blob: {}", hex::encode_upper(blob.raw))?;
            writeln!(out, "  media_type: {media_type:X}")?;
        }
        ArchivePayload::External {
            pointer,
            namespace,
            media_type,
            size,
            resolutions,
        } => {
            writeln!(out, "  external_pointer: {pointer}")?;
            writeln!(out, "  asset_namespace: {namespace:X}")?;
            if let Some(media_type) = media_type {
                writeln!(out, "  media_type: {media_type:X}")?;
            }
            if let Some(size) = size {
                writeln!(out, "  size: {size}")?;
            }
            for resolution in resolutions {
                writeln!(out, "  resolution: {}", hex::encode_upper(resolution.raw))?;
            }
        }
    }
    Ok(())
}

fn render_projection(projection: &ArchiveProjection) -> Result<String> {
    let mut out = String::new();
    writeln!(out, "projection: {:X}", projection.id)?;
    writeln!(out, "source_namespace: {:X}", projection.source_namespace)?;
    writeln!(out, "source_locator: {}", projection.source_locator)?;
    writeln!(
        out,
        "raw_record: {}",
        hex::encode_upper(projection.raw_record.raw)
    )?;
    writeln!(out, "block: {:X}", projection.block)?;
    writeln!(
        out,
        "block_timestamp: {}",
        format_interval(projection.block_timestamp)?
    )?;
    writeln!(
        out,
        "source_timestamp: {}",
        format_interval(projection.source_timestamp)?
    )?;
    for predecessor in &projection.block_previous {
        writeln!(out, "block_previous: {predecessor:X}")?;
    }
    for receipt in &projection.semantic_predecessor_support {
        writeln!(out, "semantic_predecessor_support: {receipt:X}")?;
    }
    if let Some(author) = projection.author {
        writeln!(out, "author: {author:X}")?;
    }
    if let Some(experiencer) = projection.experiencer {
        writeln!(out, "experiencer: {experiencer:X}")?;
    }
    if let Some(author) = &projection.raw_author {
        writeln!(out, "raw_author: {author}")?;
    }
    if let Some(role) = &projection.raw_role {
        writeln!(out, "raw_role: {role}")?;
    }
    if let Some(model) = &projection.raw_model {
        writeln!(out, "raw_model: {model}")?;
    }
    for path in &projection.source_paths {
        writeln!(out, "source_path: {path}")?;
    }
    for part in &projection.parts {
        render_part(&mut out, part)?;
    }
    Ok(out)
}

fn run_list(storage: ArchiveStorage<'_>, limit: usize) -> Result<()> {
    let archive = storage.load()?;
    for id in archive.recent_projection_ids(limit) {
        println!("{}", render_projection_summary(&archive.projection(id)?)?);
    }
    Ok(())
}

fn run_show(storage: ArchiveStorage<'_>, prefix: &str) -> Result<()> {
    let archive = storage.load()?;
    let id = archive.resolve_projection_prefix(prefix)?;
    print!("{}", render_projection(&archive.projection(id)?)?);
    Ok(())
}

#[derive(Clone, Debug)]
struct LoadedBlock {
    semantic: ArchiveProjection,
    receipts: Vec<ArchiveProjection>,
}

fn load_block(archive: &ArchiveSnapshot, block: Id) -> Result<LoadedBlock> {
    let receipt_ids = archive.projections_for_block(block);
    if receipt_ids.is_empty() {
        bail!("canonical Archive block {block:X} has no source projection");
    }
    let mut receipts = receipt_ids
        .into_iter()
        .map(|id| archive.projection(id))
        .collect::<Result<Vec<_>>>()?;
    receipts.sort_unstable_by_key(|projection| projection.id);
    if receipts.iter().any(|projection| projection.block != block) {
        bail!("Archive source projection lookup crossed block identities");
    }
    Ok(LoadedBlock {
        semantic: receipts[0].clone(),
        receipts,
    })
}

fn load_thread(
    archive: &ArchiveSnapshot,
    projection_prefix: &str,
    limit: usize,
) -> Result<Vec<LoadedBlock>> {
    if limit == 0 {
        bail!("thread limit must be at least 1");
    }
    let leaf = archive.resolve_projection_prefix(projection_prefix)?;
    let leaf_block = archive.projection(leaf)?.block;
    let mut pending = BTreeSet::from([leaf_block]);
    let mut nodes = BTreeMap::new();
    while let Some(block) = pending.pop_first() {
        if nodes.contains_key(&block) {
            continue;
        }
        if nodes.len() == limit {
            bail!(
                "thread ancestry exceeds {limit} canonical blocks; increase --limit so no fork is hidden"
            );
        }
        let loaded = load_block(archive, block)?;
        pending.extend(loaded.semantic.block_previous.iter().copied());
        nodes.insert(block, loaded);
    }

    let mut indegree: BTreeMap<Id, usize> = nodes
        .iter()
        .map(|(block, loaded)| (*block, loaded.semantic.block_previous.len()))
        .collect();
    let mut children = BTreeMap::<Id, BTreeSet<Id>>::new();
    for (block, loaded) in &nodes {
        for parent in &loaded.semantic.block_previous {
            children.entry(*parent).or_default().insert(*block);
        }
    }
    let mut ready: BTreeSet<Id> = indegree
        .iter()
        .filter_map(|(block, count)| (*count == 0).then_some(*block))
        .collect();
    let mut ordered = Vec::with_capacity(nodes.len());
    while let Some(block) = ready.pop_first() {
        ordered.push(nodes[&block].clone());
        for child in children.get(&block).into_iter().flatten() {
            let count = indegree
                .get_mut(child)
                .expect("every Archive child has an indegree");
            *count -= 1;
            if *count == 0 {
                ready.insert(*child);
            }
        }
    }
    if ordered.len() != nodes.len() {
        bail!("Archive thread contains a block cycle despite catalog validation");
    }
    Ok(ordered)
}

fn render_block(block: &LoadedBlock, include_all_parts: bool) -> Result<String> {
    let mut out = String::new();
    writeln!(out, "block: {:X}", block.semantic.block)?;
    writeln!(
        out,
        "timestamp: {}",
        format_interval(block.semantic.block_timestamp)?
    )?;
    for predecessor in &block.semantic.block_previous {
        writeln!(out, "previous: {predecessor:X}")?;
    }
    for receipt in &block.receipts {
        writeln!(
            out,
            "receipt: {:X} {} {}",
            receipt.id,
            receipt.source_locator,
            projection_actor(receipt),
        )?;
    }
    for part in &block.semantic.parts {
        if include_all_parts || part.modality == archive_schema::content_fact::modality::TEXT {
            render_part(&mut out, part)?;
        }
    }
    Ok(out)
}

fn run_thread(storage: ArchiveStorage<'_>, prefix: &str, limit: usize) -> Result<()> {
    let archive = storage.load()?;
    for (index, block) in load_thread(&archive, prefix, limit)?.iter().enumerate() {
        if index != 0 {
            println!("---");
        }
        print!("{}", render_block(block, true)?);
    }
    Ok(())
}

fn run_search(storage: ArchiveStorage<'_>, text: &str, limit: usize) -> Result<()> {
    let text = faculties::text_arg(text, "search text")?;
    let search = ArchiveSearchSnapshot::ensure_local(storage.pile, storage.key)?;
    for hit in search.search(&text, limit)? {
        let block = load_block(search.archive(), hit.block)?;
        println!(
            "{:.4} {} {} receipt(s) {} {}",
            hit.score,
            short_id(hit.block),
            hit.projections.len(),
            format_interval(block.semantic.block_timestamp)?,
            projection_snippet(&block.semantic),
        );
    }
    Ok(())
}

fn run_index(storage: ArchiveStorage<'_>) -> Result<()> {
    let succinct = archive_collection::ensure_succinct_index(storage.pile, storage.key)?;
    let bm25 = archive_collection::ensure_bm25_index(storage.pile, storage.key)?;
    println!(
        "Archive: {} authored element(s), {} exact raw-Succinct DERIVE record(s)",
        succinct.source_commits, succinct.derived_elements,
    );
    println!(
        "Archive BM25: {} exact derived element(s), {} resident cover segment(s)",
        bm25.derived_elements, bm25.cover_segments,
    );
    Ok(())
}

fn run_migrate_legacy(storage: ArchiveStorage<'_>) -> Result<()> {
    let source = freeze_source(storage.pile).context(
        "freeze legacy Archive source; every legacy writer must be stopped before migration",
    )?;
    let plan = archive_cutover::plan(&source)?;
    let comb_plan = comb_cutover::plan_if_present(&source)?;

    let existing = storage.load()?;
    let mut staged = Fragment::empty();
    for commit in plan.commits() {
        staged += commit.fragment().clone();
    }
    let (expected, validation) = faculties::blockdag::validate_catalog_union(
        existing.reader(),
        existing.catalog(),
        &staged,
    )?;
    require_accepted(validation, "existing Archive union legacy migration")?;
    drop(existing);

    let expected_comb = if let Some(plan) = &comb_plan {
        let (mut current, _) = storage.load_comb()?;
        current += plan.facts().clone();
        comb_model::load_catalog(&current)
            .context("validate existing Comb union legacy cursor migration")?;
        Some(current)
    } else {
        None
    };

    let commits = archive_cutover::publish(&source, &plan, storage.pile, storage.key)?;
    let comb_commits = match &comb_plan {
        Some(plan) => comb_cutover::publish(&source, plan, storage.pile, storage.key)?,
        None => Vec::new(),
    };
    let materialized = storage.load()?;
    if materialized.catalog() != &expected {
        bail!("Archive changed during stopped-world migration; published commits are replay-safe, stop every writer and retry verification");
    }
    if let Some(expected_comb) = expected_comb {
        let (actual, _) = storage.load_comb()?;
        if actual != expected_comb {
            bail!("Comb changed during stopped-world migration; published commits are replay-safe, stop every writer and retry verification");
        }
    }
    println!(
        "migrated {} authored legacy commit(s), {} fact(s), {} metafact(s); {} native COMMIT record(s)",
        plan.report().authored_commits,
        plan.report().facts,
        plan.report().metafacts,
        commits.len(),
    );
    if let Some(comb_plan) = comb_plan {
        println!(
            "migrated {} authored Comb cursor commit(s) into its separate collection ({} canonical cursor fact(s), {} native COMMIT record(s))",
            comb_plan.commits().len(),
            comb_plan.facts().len(),
            comb_commits.len(),
        );
    }
    println!("legacy branch retained as read-only migration evidence");
    Ok(())
}

fn require_accepted(validation: CatalogValidation, label: &str) -> Result<()> {
    match validation {
        CatalogValidation::Accepted => Ok(()),
        CatalogValidation::Pending { missing } => bail!(
            "{label} is missing {} attachment blob(s): {}",
            missing.len(),
            missing
                .iter()
                .take(8)
                .map(hex::encode_upper)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        CatalogValidation::Rejected(reason) => bail!("{label} is invalid: {reason}"),
    }
}

fn parse_tai_timestamp(value: &str) -> Result<Epoch> {
    let (date, time) = value
        .split_once('T')
        .ok_or_else(|| anyhow!("invalid timestamp (expected YYYY-MM-DDTHH:MM:SS): {value}"))?;
    let date = date.split('-').collect::<Vec<_>>();
    let time = time.split(':').collect::<Vec<_>>();
    if date.len() != 3 || time.len() != 3 {
        bail!("invalid timestamp (expected YYYY-MM-DDTHH:MM:SS): {value}");
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

fn cursor_state(position: Option<Epoch>) -> CursorState {
    CursorState {
        position: position.map(|epoch| (epoch, epoch).try_to_inline().unwrap()),
        grain: None,
    }
}

fn plan_cursor_update(
    catalog: &CombCatalog,
    stream: &str,
    persona: &str,
    position: Option<Epoch>,
) -> Result<Option<Fragment>> {
    let state = cursor_state(position);
    let predecessors = match catalog.resolution(stream, persona) {
        None => BTreeSet::new(),
        Some(resolution) => {
            let settled = resolution.settled_state()?;
            if matches!(resolution, CursorResolution::Unique(_)) && settled == &state {
                return Ok(None);
            }
            resolution.head_ids().into_iter().collect()
        }
    };
    let (fragment, _) = comb_model::cursor_fragment(CursorDraft {
        stream: stream.to_owned(),
        persona: persona.to_owned(),
        position: state.position,
        grain: state.grain,
        predecessors,
        observed_at: BTreeSet::new(),
    })?;
    Ok(Some(fragment))
}

fn active_cursor_position(catalog: &CombCatalog, stream: &str, persona: &str) -> Result<i128> {
    let resolution = catalog.resolution(stream, persona).ok_or_else(|| {
        anyhow!("no active replay for persona {persona}: use `archive replay start <from>`")
    })?;
    let state = resolution.settled_state()?;
    let position = state.position.ok_or_else(|| {
        anyhow!("no active replay for persona {persona}: use `archive replay start <from>`")
    })?;
    let (lower, upper): (i128, i128) = position
        .try_from_inline()
        .map_err(|error| anyhow!("decode archive replay cursor: {error:?}"))?;
    if lower != upper {
        bail!("archive replay cursor is not a point interval");
    }
    Ok(lower)
}

fn validate_cursor_update(current: &TribleSet, fragment: &Fragment) -> Result<()> {
    let mut candidate = current.clone();
    candidate += fragment.clone();
    comb_model::load_catalog(&candidate)
        .context("validate archive replay cursor successor")
        .map(|_| ())
}

fn publish_cursor_update(storage: ArchiveStorage<'_>, fragment: Fragment) -> Result<()> {
    let signer = load_signer(storage.pile, storage.key)?;
    let pile = open_pile_strict(storage.pile)?;
    let mut collection = Collection::new(pile, DEFAULT_COMB_SCOPE_ID, signer);
    let result = (|| {
        let current = collection
            .materialize()
            .context("materialize Comb cursor collection before publication")?;
        validate_cursor_update(&current, &fragment)?;
        collection
            .commit(fragment)
            .context("publish archive replay cursor")?;
        Ok(())
    })();
    finish_collection(collection, result)
}

const REPLAY_STREAM: &str = "archive-replay";

#[derive(Clone)]
struct TimelineBlock {
    key: i128,
    block: LoadedBlock,
}

fn is_dialogue(block: &LoadedBlock) -> bool {
    block
        .semantic
        .parts
        .iter()
        .any(|part| part.modality == archive_schema::content_fact::modality::TEXT)
}

fn timeline_after(
    archive: &ArchiveSnapshot,
    position: i128,
    with_tools: bool,
) -> Result<Vec<TimelineBlock>> {
    let catalog = archive.catalog();
    let mut seen = BTreeSet::new();
    let mut timeline = Vec::new();
    for (block, timestamp) in find!(
        (block: Id, timestamp: Inline<NsTAIInterval>),
        pattern!(catalog, [{ ?block @ archive_schema::block::timestamp: ?timestamp }])
    ) {
        if !seen.insert(block) {
            continue;
        }
        let key = interval_key(timestamp)?;
        if key <= position {
            continue;
        }
        let block = load_block(archive, block)?;
        if with_tools || is_dialogue(&block) {
            timeline.push(TimelineBlock { key, block });
        }
    }
    timeline.sort_unstable_by_key(|item| (item.key, item.block.semantic.block));
    Ok(timeline)
}

fn split_replay_batch(timeline: Vec<TimelineBlock>, limit: usize) -> (Vec<TimelineBlock>, usize) {
    let mut selected = Vec::new();
    let mut remaining = 0usize;
    let mut cutoff = None;
    for item in timeline {
        if selected.len() < limit || cutoff == Some(item.key) {
            cutoff = Some(item.key);
            selected.push(item);
        } else {
            remaining += 1;
        }
    }
    (selected, remaining)
}

fn run_replay(
    storage: ArchiveStorage<'_>,
    action: &[String],
    limit: usize,
    with_tools: bool,
    persona: Option<&str>,
) -> Result<()> {
    let Some(persona) = persona else {
        bail!("no persona: set $PERSONA or pass --persona; replay cursors are session bookkeeping");
    };
    if limit == 0 {
        bail!("replay limit must be at least 1");
    }

    match action.first().map(String::as_str) {
        Some("start") => {
            let Some(raw) = action.get(1) else {
                bail!("usage: archive replay start <YYYY-MM-DDTHH:MM:SS>");
            };
            if action.len() != 2 {
                bail!("usage: archive replay start <YYYY-MM-DDTHH:MM:SS>");
            }
            let from = parse_tai_timestamp(raw)?;
            let position = from - hifitime::Duration::from_total_nanoseconds(1);
            let (facts, catalog) = storage.load_comb()?;
            if let Some(fragment) =
                plan_cursor_update(&catalog, REPLAY_STREAM, persona, Some(position))?
            {
                validate_cursor_update(&facts, &fragment)?;
                publish_cursor_update(storage, fragment)?;
            }
            println!("replay started at {raw} (persona {persona})");
            return Ok(());
        }
        Some("stop") => {
            if action.len() != 1 {
                bail!("usage: archive replay stop");
            }
            let (facts, catalog) = storage.load_comb()?;
            if let Some(fragment) = plan_cursor_update(&catalog, REPLAY_STREAM, persona, None)? {
                validate_cursor_update(&facts, &fragment)?;
                publish_cursor_update(storage, fragment)?;
            }
            println!("replay stopped (persona {persona})");
            return Ok(());
        }
        Some(other) => bail!("unknown replay action `{other}` (start/stop or nothing)"),
        None => {}
    }

    let replay = storage.load_replay()?;
    let position = active_cursor_position(&replay.comb_catalog, REPLAY_STREAM, persona)?;
    let (selected, remaining) = split_replay_batch(
        timeline_after(&replay.archive, position, with_tools)?,
        limit,
    );
    if selected.is_empty() {
        println!("replay complete: nothing after the cursor. The past is read.");
        return Ok(());
    }

    for block in &selected {
        print!("{}", render_block(&block.block, with_tools)?);
        println!("---");
    }
    let last_key = selected.last().expect("selected is nonempty").key;
    let last_epoch = Epoch::from_tai_duration(hifitime::Duration::from_total_nanoseconds(last_key));
    let fragment = plan_cursor_update(
        &replay.comb_catalog,
        REPLAY_STREAM,
        persona,
        Some(last_epoch),
    )?
    .ok_or_else(|| anyhow!("replay emitted blocks without advancing its cursor"))?;
    validate_cursor_update(&replay.comb_facts, &fragment)?;
    publish_cursor_update(storage, fragment)?;
    println!(
        "batch: {} block(s); cursor -> {}; {} remaining",
        selected.len(),
        last_epoch,
        remaining,
    );
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.trace, cli.trace_filter.as_deref());
    let Some(command) = cli.command else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };
    let storage = ArchiveStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
    };
    match command {
        Command::Import { path } => run_import(storage, &path),
        Command::List { limit } => run_list(storage, limit),
        Command::Show { id } => run_show(storage, &id),
        Command::Thread { id, limit } => run_thread(storage, &id, limit),
        Command::Search { text, limit } => run_search(storage, &text, limit),
        Command::Index => run_index(storage),
        Command::MigrateLegacy => run_migrate_legacy(storage),
        Command::Replay {
            action,
            limit,
            with_tools,
            persona,
        } => run_replay(storage, &action, limit, with_tools, persona.as_deref()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use faculties::collection_cutover::initialize_signer;
    use std::fs;

    struct Fixture {
        _directory: tempfile::TempDir,
        pile: PathBuf,
        key: PathBuf,
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("archive.pile");
        fs::File::create(&pile).unwrap();
        let key = directory.path().join("archive.key");
        initialize_signer(&pile, Some(&key)).unwrap();
        Fixture {
            _directory: directory,
            pile,
            key,
        }
    }

    fn storage(fixture: &Fixture) -> ArchiveStorage<'_> {
        ArchiveStorage {
            pile: &fixture.pile,
            key: Some(&fixture.key),
        }
    }

    fn archive_root_count(fixture: &Fixture) -> usize {
        storage(fixture).load().unwrap().commits().len()
    }

    #[test]
    fn cli_surface_has_no_branch_sidecar_or_legacy_importer_controls() {
        let commands: BTreeSet<_> = Cli::command()
            .get_subcommands()
            .map(|command| command.get_name().to_owned())
            .collect();
        assert_eq!(
            commands,
            [
                "import",
                "index",
                "list",
                "migrate-legacy",
                "replay",
                "search",
                "show",
                "thread",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        assert!(Cli::try_parse_from([
            "archive",
            "--pile",
            "archive.pile",
            "--branch",
            "archive",
            "list"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "archive",
            "--pile",
            "archive.pile",
            "--branch-id",
            "11111111111111111111111111111111",
            "show",
            "1111"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "archive",
            "--pile",
            "archive.pile",
            "index",
            "--prepare-in-flight",
            "4"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "archive",
            "--pile",
            "archive.pile",
            "import",
            "chatgpt",
            "backup"
        ])
        .is_err());
    }

    #[test]
    fn cli_import_publishes_one_signed_visibility_edge() {
        let fixture = fixture();
        let source = fixture._directory.path().join("claude-code");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("parent.jsonl"),
            r#"{"type":"user","sessionId":"atomic","uuid":"root","timestamp":"2026-03-01T15:34:01Z","message":{"role":"user","content":"parent"}}"#,
        )
        .unwrap();
        fs::write(
            source.join("child.jsonl"),
            r#"{"type":"assistant","sessionId":"atomic","uuid":"child","parentUuid":"root","timestamp":"2026-03-01T15:34:02Z","message":{"role":"assistant","content":"child"}}"#,
        )
        .unwrap();

        run_import(storage(&fixture), &source).unwrap();
        assert_eq!(archive_root_count(&fixture), 1);
        let archive = storage(&fixture).load().unwrap();
        assert_eq!(archive.projection_ids().len(), 2);
        drop(archive);
        let after_first = fs::metadata(&fixture.pile).unwrap().len();

        run_import(storage(&fixture), &source).unwrap();
        assert_eq!(archive_root_count(&fixture), 1);
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), after_first);
    }

    #[test]
    fn failed_cli_import_leaves_no_signed_archive_root() {
        let fixture = fixture();
        let source = fixture._directory.path().join("conflict");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("origin.jsonl"),
            r#"{"type":"user","sessionId":"origin","uuid":"message","message":{"role":"user","content":"origin"}}"#,
        )
        .unwrap();
        fs::write(
            source.join("fork.jsonl"),
            r#"{"type":"user","sessionId":"fork","uuid":"copy","forkedFrom":{"sessionId":"origin","messageUuid":"message"},"message":{"role":"user","content":"different"}}"#,
        )
        .unwrap();

        let error = run_import(storage(&fixture), &source).unwrap_err();
        assert!(format!("{error:#}").contains("conflicting semantic payloads"));
        assert_eq!(archive_root_count(&fixture), 0);
    }

    #[test]
    fn raw_succinct_and_bm25_derives_are_idempotent_and_search_works() {
        let fixture = fixture();
        let source = fixture._directory.path().join("one.jsonl");
        fs::write(
            &source,
            r#"{"type":"user","sessionId":"read","uuid":"one","timestamp":"2026-03-01T15:34:01Z","message":{"role":"user","content":"quasar needle"}}"#,
        )
        .unwrap();
        run_import(storage(&fixture), &source).unwrap();
        let first =
            archive_collection::ensure_succinct_index(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(first.source_commits, 1);
        assert_eq!(first.derived_elements, 1);
        assert_ne!(first.source_collection, first.target_collection);
        let before = fs::metadata(&fixture.pile).unwrap().len();

        let archive = storage(&fixture).load().unwrap();
        let id = archive.projection_ids()[0];
        let projection = archive.projection(id).unwrap();
        assert!(render_projection(&projection)
            .unwrap()
            .contains("quasar needle"));
        assert_eq!(
            load_thread(&archive, &format!("{id:X}"), 10).unwrap().len(),
            1
        );
        drop(archive);
        let repeated =
            archive_collection::ensure_succinct_index(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(repeated, first);

        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), before);

        let first_bm25 =
            archive_collection::ensure_bm25_index(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(first_bm25.source_commits, 1);
        assert_eq!(first_bm25.derived_elements, 1);
        assert_eq!(first_bm25.cover_segments, 1);
        let after_bm25 = fs::metadata(&fixture.pile).unwrap().len();
        assert_eq!(
            archive_collection::ensure_bm25_index(&fixture.pile, Some(&fixture.key)).unwrap(),
            first_bm25
        );
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), after_bm25);

        let search =
            ArchiveSearchSnapshot::ensure_local(&fixture.pile, Some(&fixture.key)).unwrap();
        let hits = search.search("quasar", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].projections, [id]);
        drop(search);
        run_search(storage(&fixture), "quasar", 10).unwrap();
    }

    #[test]
    fn thread_keeps_every_parent_of_a_multi_parent_block() {
        let fixture = fixture();
        let source = fixture._directory.path().join("fork.jsonl");
        fs::write(
            &source,
            concat!(
                r#"{"type":"user","sessionId":"fork","uuid":"left","message":{"role":"user","content":"left"}}"#,
                "\n",
                r#"{"type":"user","sessionId":"fork","uuid":"right","message":{"role":"user","content":"right"}}"#,
                "\n",
                r#"{"type":"assistant","sessionId":"fork","uuid":"join","parentUuid":"left","message":{"role":"assistant","content":"joined"}}"#,
                "\n",
                r#"{"type":"assistant","sessionId":"fork","uuid":"join","parentUuid":"right","message":{"role":"assistant","content":"joined"}}"#,
            ),
        )
        .unwrap();
        run_import(storage(&fixture), &source).unwrap();
        let archive = storage(&fixture).load().unwrap();
        let joined = archive
            .projection_ids()
            .into_iter()
            .find(|id| {
                archive
                    .projection(*id)
                    .is_ok_and(|projection| projection_snippet(&projection).contains("joined"))
            })
            .unwrap();
        let thread = load_thread(&archive, &format!("{joined:X}"), 3).unwrap();
        assert_eq!(thread.len(), 3);
        let parent_count: usize = thread
            .iter()
            .map(|block| block.semantic.block_previous.len())
            .sum();
        assert_eq!(parent_count, 2);
        assert!(load_thread(&archive, &format!("{joined:X}"), 2)
            .unwrap_err()
            .to_string()
            .contains("no fork is hidden"));
    }

    #[test]
    fn replay_rejects_zero_limit_and_never_splits_equal_timestamps() {
        let fixture = fixture();
        let source = fixture._directory.path().join("replay.jsonl");
        fs::write(
            &source,
            concat!(
                r#"{"type":"user","sessionId":"replay","uuid":"first","timestamp":"2026-03-01T15:34:01Z","message":{"role":"user","content":"first"}}"#,
                "\n",
                r#"{"type":"user","sessionId":"replay","uuid":"second","timestamp":"2026-03-01T15:34:01Z","message":{"role":"user","content":"second"}}"#,
                "\n",
                r#"{"type":"user","sessionId":"replay","uuid":"third","timestamp":"2026-03-01T15:34:02Z","message":{"role":"user","content":"third"}}"#,
            ),
        )
        .unwrap();
        run_import(storage(&fixture), &source).unwrap();

        let archive = storage(&fixture).load().unwrap();
        let timeline = timeline_after(&archive, i128::MIN, false).unwrap();
        assert_eq!(timeline.len(), 3);
        let (selected, remaining) = split_replay_batch(timeline, 1);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].key, selected[1].key);
        assert_eq!(remaining, 1);

        let error = run_replay(storage(&fixture), &[], 0, false, Some("replay-test")).unwrap_err();
        assert_eq!(error.to_string(), "replay limit must be at least 1");
    }
}
