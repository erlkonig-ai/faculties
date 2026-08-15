use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser};
use faculties::collection_cutover::{freeze_source, load_signer, open_pile_strict};
use faculties::schemas::embeddings::DEFAULT_SCOPE_ID as EMBEDDINGS_SCOPE_ID;
#[cfg(feature = "local-embed")]
use faculties::schemas::embeddings::{self, Embedding768};
use faculties::schemas::memory::{
    archive_schema as legacy_archive_schema, ctx, DEFAULT_COMB_SCOPE_ID,
    DEFAULT_SCOPE_ID as MEMORY_SCOPE_ID,
};
use faculties::schemas::{blockdag as archive_schema, cognition as cognition_schema};
// The context-cover renderer and its chunk accessors live in the lib module
// `faculties::memory_cover` so `orient wake` can assemble the same cover
// in-process. Re-import the pieces this binary still uses elsewhere.
use faculties::memory_cover::{
    all_chunk_ids, chunk_end_at, chunk_image_handle, chunk_lens_handle, chunk_span_str,
    chunk_start_at, chunk_summary_handle, collect_chunk_spans, epoch_end_from_interval,
    epoch_from_interval, fmt_epoch, format_time_range, interval_key, key_to_epoch, superseded_ids,
    CoverOpts, DEFAULT_SIM_THRESHOLD,
};
#[cfg(feature = "local-embed")]
use faculties::memory_cover::{chunk_embedding_handle, l2_normalize};
use faculties::{
    blockdag::{self, CatalogValidation},
    cognition as cognition_model, comb as comb_model, memory as memory_model, memory_cutover,
};
use hifitime::Epoch;
use triblespace::core::blob::Bytes;
use triblespace::core::collection::Collection;
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet};
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::{LongString, RawBytes};
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval};
use triblespace::prelude::*;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "memory",
    about = "Show compacted context chunks (drill down by narrowing the time range).\n\n\
             Subcommands:\n  \
             memory <from>..<to>              — show best summary covering a time range\n  \
             memory meta <from>..<to>         — show structural metadata for a time range\n  \
             memory context [<budget>] [--chars N] [--about <query>] [--filter <query>] [--remove <query>] [--sim-threshold <f>] — antichain cover over ALL memories, coarse→fine to a CHARACTER budget (bare <budget>, --chars N, or the --tokens N alias all count CHARACTERS — there is no token estimate); --about biases detail toward memories relevant to <query> by MEANING (semantic, via `memory embed`; otherwise exact lexical BM25 is rebuilt automatically); --filter <query> keeps ONLY chunks whose positive similarity to <query> exceeds --sim-threshold (default 0.55); --remove <query> is the anti-filter — drops chunks whose similarity EXCEEDS the threshold (negate in the retrieval, NOT the query text; do not phrase a negation). Filter/remove decide eligibility, --about weights detail among the eligible, budget decides coarseness; they compose. NOTE: gating is chunk-level — a surviving COARSE ancestor's pre-written summary may still mention removed material. Unembedded wordless images are kept (fail-open) with a stderr warning.\n  \
             memory cover start [--chars N] [--chunk-chars M] [--session KEY] — generate the context cover (exactly `memory context --chars N`; N=400000) and store it for cursor-chunked reading in ~M-char chunks (M=20000); state lives in `${XDG_CACHE_HOME:-~/.cache}/faculties/cover/<KEY>/`, NOT the pile\n  \
             memory cover continue [--session KEY] — print the next stored chunk and advance the cursor; the final chunk ends with `COVER COMPLETE K/K`\n  \
             memory cover status [--session KEY]  — one line: complete=<true|false> loaded=<i>/<K> chars=<X>/<Y>; exit 0 when complete, 1 when not (hook-friendly)\n  \
             memory cover reset [--session KEY]   — rewind the cursor to 0 (does NOT regenerate the stored cover)\n  \
             memory density [<grain>]        — find where the hierarchy is BUSHY (many flat leaf-children under one span, no intermediate arc summary) vs balanced vs coarse; worst-first\n  \
             memory search <query>           — exact lexical (BM25) search rebuilt from the frozen Memory view\n  \
             memory similar <query>           — semantic search: nearest chunks by MEANING in the shared nomic space (build/refresh with `memory embed`) [needs --features local-embed]\n  \
             memory lens [<theme>]            — thematic lenses beside the spine: list them, or print a theme's narratives (create with `create --lens <theme>`)\n  \
             memory list [<grain>]            — show chunk time-ranges only: containment outline, or one zoom layer (no content)\n  \
             memory check <grain>             — report coverage gaps at a coarseness level (chunks of width <= grain)\n  \
             memory create [<range>] <summary> — create a memory chunk\n  \
             memory image <when> <image-path> — create a WORDLESS image memory at a time-coordinate (embed with `memory embed`; ranks in `memory similar` beside text) [needs --features local-embed to embed]\n  \
             memory respan <id> <from>..<to>  — correct a chunk's span (new chunk supersedes old; views exclude old)\n  \
             memory supersede <new> <old>     — mark an existing chunk as replacing another (old leaves all views)\n  \
             memory retract <id> [reason]      — retire a mistaken/duplicate chunk with NO replacement (invisible tombstone; target leaves all views, nothing new shows up as a memory)\n  \
             memory retractions               — audit surface: list retractions (what was retracted, and why)\n  \
             memory migrate-legacy            — additively publish the frozen legacy memory branch as native commits (stop every legacy writer first)\n  \
             memory consolidate start <ts> | <ts> <summary> | stop — write chunks from an advancing edge ($PERSONA cursor)\n  \
             memory replay start <grain> [<from>] | [<count>] | stop — stream the memory at a zoom level ($PERSONA cursor)\n  \
             memory provenance <chunk-id>     — list cognition + archive events overlapping the chunk's time range\n\n\
             Time format: YYYY-MM-DDTHH:MM:SS..YYYY-MM-DDTHH:MM:SS (TAI)\n\
             Hex id prefixes also accepted as fallback."
)]
struct Cli {
    /// Path to the pile file to use.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// One or more time ranges / id prefixes to show, or `turn <turn-id>`, or `create [<from>..<to>] <summary>`.
    #[arg(value_name = "ID", trailing_var_arg = true, allow_hyphen_values = true)]
    ids: Vec<String>,
}

#[derive(Clone, Copy)]
struct MemoryStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

struct CollectionView {
    facts: TribleSet,
    reader: PileReader,
}

struct LoadedMemory {
    memory: CollectionView,
    catalog: memory_model::MemoryCatalog,
}

struct LoadedContext {
    memory: LoadedMemory,
    embeddings: CollectionView,
}

struct LoadedComb {
    memory: LoadedMemory,
    comb_catalog: comb_model::CombCatalog,
}

struct LoadedProvenance {
    memory: LoadedMemory,
    cognition: CollectionView,
    archive: CollectionView,
}

impl MemoryStorage<'_> {
    fn materialize_scope(
        pile: &mut Pile,
        signer: &ed25519_dalek::SigningKey,
        scope: Id,
        label: &str,
    ) -> Result<TribleSet> {
        let mut collection = Collection::new(&mut *pile, scope, signer.clone());
        collection
            .materialize()
            .with_context(|| format!("materialize authored {label} collection"))
    }

    fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
        let close = pile.close();
        match (result, close) {
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) => Err(anyhow!("close pile: {error}")),
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(close_error)) => {
                Err(error.context(format!("closing pile also failed: {close_error}")))
            }
        }
    }

    fn load_memory_from_pile(
        pile: &mut Pile,
        signer: &ed25519_dalek::SigningKey,
    ) -> Result<LoadedMemory> {
        let materialized = Self::materialize_scope(pile, signer, MEMORY_SCOPE_ID, "Memory")?;
        let reader = pile.reader().context("open Memory blob reader")?;
        let catalog = memory_model::validate_catalog(&reader, &materialized)
            .context("validate Memory collection")?;
        // The collection remains an exact additive ledger.  Ordinary Memory
        // commands consume its canonical projection so preserved random-id
        // legacy rows and rebuildable exhaust cannot leak back into covers,
        // searches, or direct chunk enumeration.
        let nodes = catalog.node_ids();
        let mut facts = TribleSet::new();
        for fact in materialized.iter().filter(|fact| nodes.contains(fact.e())) {
            facts.insert(fact);
        }
        let memory = CollectionView { facts, reader };
        Ok(LoadedMemory { memory, catalog })
    }

    /// Freeze canonical Memory alone for ordinary commands.
    fn load(&self) -> Result<LoadedMemory> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = Self::load_memory_from_pile(&mut pile, &signer);
        Self::finish_pile(pile, result)
    }

    /// Freeze Memory and shared Embeddings from one snapshot for semantic or
    /// context-cover reads.
    fn load_context(&self, with_embeddings: bool) -> Result<LoadedContext> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = (|| {
            let memory = Self::load_memory_from_pile(&mut pile, &signer)?;
            let facts = if with_embeddings {
                Self::materialize_scope(
                    &mut pile,
                    &signer,
                    EMBEDDINGS_SCOPE_ID,
                    "shared Embeddings",
                )?
            } else {
                TribleSet::new()
            };
            let embeddings = CollectionView {
                facts,
                reader: memory.memory.reader.clone(),
            };
            Ok(LoadedContext { memory, embeddings })
        })();
        Self::finish_pile(pile, result)
    }

    /// Freeze Memory and Comb together for cursor transitions.
    fn load_comb(&self) -> Result<LoadedComb> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = (|| {
            let memory = Self::load_memory_from_pile(&mut pile, &signer)?;
            let facts = Self::materialize_scope(&mut pile, &signer, DEFAULT_COMB_SCOPE_ID, "Comb")?;
            let comb = CollectionView {
                facts,
                reader: memory.memory.reader.clone(),
            };
            let comb_catalog =
                comb_model::load_catalog(&comb.facts).context("validate Comb collection")?;
            Ok(LoadedComb {
                memory,
                comb_catalog,
            })
        })();
        Self::finish_pile(pile, result)
    }

    /// Freeze Memory, Cognition, and Archive from exactly one pile snapshot
    /// for a coherent cross-scope provenance read.
    fn load_provenance(&self) -> Result<LoadedProvenance> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = (|| {
            let memory = Self::load_memory_from_pile(&mut pile, &signer)?;
            let cognition_facts = Self::materialize_scope(
                &mut pile,
                &signer,
                cognition_schema::DEFAULT_SCOPE_ID,
                "Cognition",
            )?;
            let archive_facts = Self::materialize_scope(
                &mut pile,
                &signer,
                archive_schema::DEFAULT_SCOPE_ID,
                "Archive",
            )?;
            let reader = memory.memory.reader.clone();
            match blockdag::validate_catalog(&reader, &archive_facts)
                .context("validate Archive collection for Memory provenance")?
            {
                CatalogValidation::Accepted => {}
                CatalogValidation::Pending { missing } => bail!(
                    "Archive collection is missing {} attachment blob(s)",
                    missing.len()
                ),
                CatalogValidation::Rejected(reason) => {
                    bail!("Archive collection is invalid: {reason}")
                }
            }
            Ok(LoadedProvenance {
                memory,
                cognition: CollectionView {
                    facts: cognition_facts,
                    reader: reader.clone(),
                },
                archive: CollectionView {
                    facts: archive_facts,
                    reader,
                },
            })
        })();
        Self::finish_pile(pile, result)
    }

    fn publish_memory(&self, _loaded: &LoadedMemory, fragment: Fragment) -> Result<()> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = (|| {
            let current = Self::materialize_scope(&mut pile, &signer, MEMORY_SCOPE_ID, "Memory")?;
            let reader = pile.reader().context("open Memory mutation reader")?;
            memory_model::validate_candidate(&reader, &current, &fragment)
                .context("validate Memory mutation")?;
            let mut collection = Collection::new(&mut pile, MEMORY_SCOPE_ID, signer.clone());
            collection
                .commit(fragment)
                .context("commit authored Memory fragment")?;
            Ok(())
        })();
        Self::finish_pile(pile, result)
    }

    #[cfg(feature = "local-embed")]
    fn publish_embeddings(&self, fragment: Fragment) -> Result<()> {
        let signer = load_signer(self.pile, self.key)?;
        let pile = open_pile_strict(self.pile)?;
        let mut collection = Collection::new(pile, EMBEDDINGS_SCOPE_ID, signer);
        let result = collection
            .commit(fragment)
            .context("commit authored embedding observations")
            .map(|_| ());
        Self::finish_pile(collection.into_storage(), result)
    }

    fn publish_comb(&self, loaded: &LoadedComb, fragment: Fragment) -> Result<()> {
        let _ = loaded;
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = (|| {
            let mut candidate =
                Self::materialize_scope(&mut pile, &signer, DEFAULT_COMB_SCOPE_ID, "Comb")?;
            candidate += fragment.facts().clone();
            comb_model::load_catalog(&candidate).context("validate Comb mutation")?;
            let mut collection = Collection::new(&mut pile, DEFAULT_COMB_SCOPE_ID, signer.clone());
            collection
                .commit(fragment)
                .context("commit authored Comb cursor")?;
            Ok(())
        })();
        Self::finish_pile(pile, result)
    }
}

// ── on-demand chunk queries ───────────────────────────────────────────
// Chunks are queried directly from the TribleSet — no pre-materialization.

/// One-line render of a chunk for list/similar output: the summary's first
/// line, or a wordless-image marker, or empty.
fn chunk_oneline(reader: &PileReader, space: &TribleSet, id: Id) -> String {
    if let Some(h) = chunk_summary_handle(space, id) {
        return reader
            .get::<View<str>, LongString>(h)
            .ok()
            .map(|v| v.as_ref().lines().next().unwrap_or("").to_string())
            .unwrap_or_default();
    }
    if chunk_image_handle(space, id).is_some() {
        return format!("[image memory @ {}]", chunk_span_str(space, id));
    }
    String::new()
}

/// Outgoing contextual references of a canonical chunk.
fn chunk_references(space: &TribleSet, id: Id) -> Vec<Id> {
    let mut children: Vec<Id> =
        find!(c: Id, pattern!(space, [{ id @ ctx::reference: ?c }])).collect();
    // Sort referenced chunks by their start_at time.
    let superseded = superseded_ids(space);
    children.retain(|child_id| !superseded.contains(child_id));
    children.sort_by_key(|child_id| {
        chunk_start_at(space, *child_id)
            .map(interval_key)
            .unwrap_or(i128::MAX)
    });
    children.dedup();
    children
}

fn chunk_about_exec_result(space: &TribleSet, id: Id) -> Option<Id> {
    find!(v: Id, pattern!(space, [{ id @ ctx::about_exec_result: ?v }])).next()
}

// ---------------------------------------------------------------------------
// time-range helpers
// ---------------------------------------------------------------------------

fn parse_tai_timestamp(s: &str) -> Result<Epoch> {
    // Parse "YYYY-MM-DDTHH:MM:SS"
    let parts: Vec<&str> = s.split('T').collect();
    if parts.len() != 2 {
        bail!("invalid timestamp: {s}");
    }
    let date_parts: Vec<&str> = parts[0].split('-').collect();
    let time_parts: Vec<&str> = parts[1].split(':').collect();
    if date_parts.len() != 3 || time_parts.len() != 3 {
        bail!("invalid timestamp: {s}");
    }
    let y: i32 = date_parts[0].parse().context("year")?;
    let m: u8 = date_parts[1].parse().context("month")?;
    let d: u8 = date_parts[2].parse().context("day")?;
    let hh: u8 = time_parts[0].parse().context("hour")?;
    let mm: u8 = time_parts[1].parse().context("minute")?;
    let ss: u8 = time_parts[2].parse().context("second")?;
    Ok(Epoch::from_gregorian_tai(y, m, d, hh, mm, ss, 0))
}

fn parse_time_range(s: &str) -> Result<(Epoch, Epoch)> {
    let Some((from_str, to_str)) = s.split_once("..") else {
        bail!("invalid time range (expected `from..to`): {s}");
    };
    let from = parse_tai_timestamp(from_str).context("parsing range start")?;
    let to = parse_tai_timestamp(to_str).context("parsing range end")?;
    Ok((from, to))
}

/// Find the best chunk covering a query time range — the most *specific*
/// summary, by overlap, at a scale matching the query.
///
/// Each overlapping chunk is scored `2*overlap - width = overlap - (width -
/// overlap)`: it rewards covering the query and penalises span wasted outside
/// it. A snug cover (width ≈ overlap ≈ query) wins; a vastly wider container
/// (e.g. a whole-life root) scores deeply negative and only wins when the
/// query itself is whole-life-scale; a sub-query moment scores below a cover
/// that matches the query's width. This replaces a "narrowest strict
/// container, else max raw overlap" rule that let an oversized root shadow
/// every finer cover (raw overlap also favours wide chunks).
fn find_chunk_by_time_range(space: &TribleSet, query_start: Epoch, query_end: Epoch) -> Option<Id> {
    let query_start_ns = query_start.to_tai_duration().total_nanoseconds();
    let query_end_ns = query_end.to_tai_duration().total_nanoseconds();

    let mut best: Option<(Id, i128)> = None; // (id, specificity score)

    let superseded = superseded_ids(space);
    for chunk_id in all_chunk_ids(space) {
        if superseded.contains(&chunk_id) {
            continue;
        }
        let start_val = chunk_start_at(space, chunk_id);
        let end_val = chunk_end_at(space, chunk_id);
        let (Some(start_v), Some(end_v)) = (start_val, end_val) else {
            continue;
        };

        let chunk_start = epoch_from_interval(start_v)
            .to_tai_duration()
            .total_nanoseconds();
        let chunk_end = epoch_end_from_interval(end_v)
            .to_tai_duration()
            .total_nanoseconds();

        if chunk_start > query_end_ns || chunk_end < query_start_ns {
            continue;
        }

        let overlap_start = chunk_start.max(query_start_ns);
        let overlap_end = chunk_end.min(query_end_ns);
        let overlap = overlap_end.saturating_sub(overlap_start);
        let width = chunk_end - chunk_start;
        let score = 2 * overlap - width;
        match best {
            Some((_, prev_score)) if prev_score >= score => {}
            _ => best = Some((chunk_id, score)),
        }
    }

    best.map(|(id, _)| id)
}

// ── exact BM25 search over the frozen Memory collection ───────────────

fn cmd_search(storage: MemoryStorage<'_>, args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("usage: memory search <query words...>");
    }
    let query = args.join(" ");
    let loaded = storage.load()?;
    let mut rows: Vec<(Id, f32)> = faculties::memory_cover::lexical_relevance_scores(
        &loaded.memory.facts,
        &loaded.memory.reader,
        &query,
    )?
    .into_iter()
    .collect();
    rows.sort_unstable_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    if rows.is_empty() {
        println!("no matches.");
        return Ok(());
    }
    for (chunk, score) in rows.into_iter().take(10) {
        let summary = chunk_oneline(&loaded.memory.reader, &loaded.memory.facts, chunk);
        println!("{score:6.2}  {chunk:x}  {summary}");
    }
    Ok(())
}

// ── semantic embedding seam (nomic shared-space observations) ───────────────
// Unlike exact BM25, semantic retrieval needs a durable shared-space
// observation: `memory embed` embeds each chunk summary once with
// nomic-embed-text, store the 768-d vector as exhaust under the chunk's id),
// `memory similar` is the query (embed the query, nearest over stored vectors).
// Where BM25 matches tokens, this matches MEANING — a paraphrase with no shared
// words still recalls the right memory. The vectors live in the SAME
// `embeddings::attr::embedding` space as files/photos, so this is the memory end
// of one cross-faculty semantic search: a text query here is directly
// comparable to an image candidate there (nomic text+vision are co-embedded).
//
// Both embedders load ENTIRELY from one immutable native Mary collection
// snapshot per model pile — weights and tokenizer — via the shared
// `faculties::nomic` seam. Import and legacy migration belong in Mary, outside
// ordinary memory operation.

#[cfg(feature = "local-embed")]
use faculties::nomic;

/// `memory embed` — embed every live chunk summary that lacks a vector and
/// store it as an observation in the shared Embeddings collection. Idempotent:
/// re-running only embeds live chunks absent from the frozen observation set.
#[cfg(feature = "local-embed")]
fn cmd_embed(storage: MemoryStorage<'_>) -> Result<()> {
    use mary::embed::LocalEmbedder;

    // What a chunk embeds FROM: its summary prose (nomic-text) or its raw image
    // bytes (nomic-vision). Both land on the same `embeddings::attr::embedding`
    // because nomic text+vision share one 768-d space.
    enum Src {
        Text(Inline<Handle<LongString>>),
        Image(Inline<Handle<RawBytes>>),
    }

    let loaded = storage.load_context(true)?;
    let space = &loaded.memory.memory.facts;
    let mut todo: Vec<(Id, Src)> = Vec::new();
    for chunk in loaded.memory.catalog.live_chunk_ids() {
        if chunk_embedding_handle(&loaded.embeddings.facts, chunk)?.is_some() {
            continue;
        }
        // An image chunk is wordless — route it to vision; otherwise embed
        // its summary with text. (A validated chunk has exactly one.)
        if let Some(h) = chunk_image_handle(space, chunk) {
            todo.push((chunk, Src::Image(h)));
        } else if let Some(h) = chunk_summary_handle(space, chunk) {
            todo.push((chunk, Src::Text(h)));
        }
    }
    if todo.is_empty() {
        println!("all live chunks already embedded.");
        return Ok(());
    }
    let total = todo.len();

    // Load each model once, lazily — a pile with only text memories never
    // pays for the vision weights, and vice versa.
    let mut text_emb: Option<mary::embed::NomicTextEmbedder<_>> = None;
    let mut vision_emb: Option<mary::embed::NomicVisionEmbedder<_>> = None;
    let mut n_text = 0usize;
    let mut n_image = 0usize;
    let mut fragment = Fragment::empty();
    for (i, (chunk, src)) in todo.into_iter().enumerate() {
        let v = match src {
            Src::Text(sh) => {
                let summary: View<str> = loaded
                    .memory
                    .memory
                    .reader
                    .get(sh)
                    .context("read chunk summary")?;
                let emb = match &text_emb {
                    Some(e) => e,
                    None => {
                        eprintln!("memory: loading nomic-embed-text (once)…");
                        text_emb = Some(nomic::load_text_embedder()?);
                        text_emb.as_ref().unwrap()
                    }
                };
                n_text += 1;
                l2_normalize(
                    emb.embed_document(summary.as_ref())
                        .map_err(|e| anyhow!("embed chunk {chunk:x}: {e:?}"))?,
                )
            }
            Src::Image(ih) => {
                let bytes: Bytes = loaded
                    .memory
                    .memory
                    .reader
                    .get(ih)
                    .context("read image bytes")?;
                let emb = match &vision_emb {
                    Some(e) => e,
                    None => {
                        eprintln!("memory: loading nomic-embed-vision (once)…");
                        vision_emb = Some(nomic::load_vision_embedder()?);
                        vision_emb.as_ref().unwrap()
                    }
                };
                n_image += 1;
                l2_normalize(
                    emb.embed_image(bytes.as_ref())
                        .map_err(|e| anyhow!("embed image chunk {chunk:x}: {e:?}"))?,
                )
            }
        };
        let handle = fragment.put::<Embedding768, _>(v);
        fragment += entity! { triblespace::core::id::ExclusiveId::force_ref(&chunk) @ embeddings::attr::embedding: handle };
        if (i + 1) % 25 == 0 || i + 1 == total {
            eprintln!("  embedded {}/{total}", i + 1);
        }
    }
    storage.publish_embeddings(fragment)?;
    println!("embedded {n_text} text + {n_image} image chunk(s) into the shared nomic space.");
    Ok(())
}

#[cfg(not(feature = "local-embed"))]
fn cmd_embed(_storage: MemoryStorage<'_>) -> Result<()> {
    bail!("`memory embed` needs the local embedder — rebuild with `--features local-embed`");
}

/// `memory similar <query>` — nearest chunks to a free-text query in the shared
/// nomic space. Matches by meaning, not tokens (the semantic complement to
/// `memory search`). Reads stored vectors only; `memory embed` builds them.
#[cfg(feature = "local-embed")]
fn cmd_similar(storage: MemoryStorage<'_>, args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("usage: memory similar <query words...>");
    }
    let query = args.join(" ");
    eprintln!("memory: loading nomic-embed-text (once)…");
    let emb = nomic::load_text_embedder()?;
    let qv = l2_normalize(
        emb.embed_query(&query)
            .map_err(|e| anyhow!("embed query: {e:?}"))?,
    );

    let loaded = storage.load_context(true)?;
    let space = &loaded.memory.memory.facts;
    let mut pairs: Vec<(Id, Vec<f32>)> = Vec::new();
    for chunk in loaded.memory.catalog.live_chunk_ids() {
        if let Some(h) = chunk_embedding_handle(&loaded.embeddings.facts, chunk)? {
            let v: View<[f32]> = loaded
                .embeddings
                .reader
                .get(h)
                .map_err(|e| anyhow!("read embedding: {e:?}"))?;
            pairs.push((chunk, v.as_ref().to_vec()));
        }
    }
    if pairs.is_empty() {
        bail!("no chunk embeddings on this pile yet — run `memory embed` first");
    }
    if pairs.len() < loaded.memory.catalog.live_chunk_ids().len() {
        eprintln!(
            "note: {} live chunk(s) not yet embedded — run `memory embed` to refresh",
            loaded.memory.catalog.live_chunk_ids().len() - pairs.len()
        );
    }
    let ranked = embeddings::nearest(&pairs, &qv, 0.0).map_err(|e| anyhow!("nearest: {e:?}"))?;
    if ranked.is_empty() {
        println!("no matches.");
        return Ok(());
    }
    for (cos, chunk) in ranked.into_iter().take(10) {
        let span = match (chunk_start_at(space, chunk), chunk_end_at(space, chunk)) {
            (Some(s), Some(e)) => {
                let (s, _): (Epoch, Epoch) = s.try_from_inline().unwrap();
                let (e, _): (Epoch, Epoch) = e.try_from_inline().unwrap();
                format_time_range(s, e)
            }
            _ => "?".to_string(),
        };
        let summary = chunk_oneline(&loaded.memory.memory.reader, space, chunk);
        let img_line = match chunk_image_handle(space, chunk) {
            Some(h) => match materialize_image(&loaded.memory.memory.reader, chunk, h) {
                Ok(path) => format!("\n        → {} (Read this path to view)", path.display()),
                Err(e) => format!("\n        (image export failed: {e})"),
            },
            None => String::new(),
        };
        println!("{cos:6.3}  {chunk:x}  {span}\n        {summary}{img_line}");
    }
    Ok(())
}

#[cfg(not(feature = "local-embed"))]
fn cmd_similar(_storage: MemoryStorage<'_>, _args: &[String]) -> Result<()> {
    bail!("`memory similar` needs the local embedder — rebuild with `--features local-embed`");
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.ids.is_empty() {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    }
    let storage = MemoryStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
    };

    // Dispatch to subcommand handlers.
    if cli.ids.first().is_some_and(|value| value == "create") {
        return cmd_create(storage, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "image") {
        return cmd_image(storage, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "meta") {
        return cmd_meta(storage, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "respan") {
        return cmd_respan(storage, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "supersede") {
        return cmd_supersede(storage, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "retract") {
        return cmd_retract(storage, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "retractions") {
        return cmd_retractions(storage, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "provenance") {
        return cmd_provenance(storage, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "consolidate") {
        return cmd_consolidate(storage, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "replay") {
        return cmd_replay(storage, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "search") {
        return cmd_search(storage, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "embed") {
        return cmd_embed(storage);
    }
    if cli.ids.first().is_some_and(|value| value == "similar") {
        return cmd_similar(storage, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "context") {
        return cmd_context(storage, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "cover") {
        return cmd_cover(storage, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "lens") {
        return cmd_lens(storage, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "list") {
        return cmd_list(storage, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "check") {
        return cmd_check(storage, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "density") {
        return cmd_density(storage, &cli.ids[1..]);
    }
    if cli
        .ids
        .first()
        .is_some_and(|value| value == "migrate-legacy")
    {
        if cli.ids.len() != 1 {
            bail!("usage: memory migrate-legacy");
        }
        return cmd_migrate_legacy(storage);
    }

    let loaded = storage.load()?;
    if cli.ids.first().is_some_and(|value| value == "turn") {
        if cli.ids.len() != 2 {
            bail!("usage: memory turn <turn-id>");
        }
        return print_turn_facets(&loaded.memory.reader, &loaded.memory.facts, &cli.ids[1]);
    }

    let mut first = true;
    for raw in &cli.ids {
        let chunk_id = if raw.contains("..") {
            let (start, end) = parse_time_range(raw)?;
            find_chunk_by_time_range(&loaded.memory.facts, start, end)
                .ok_or_else(|| anyhow!("no memory covers range {raw}"))?
        } else {
            match resolve_chunk_id(&loaded, raw) {
                Ok(id) => id,
                Err(err) => {
                    return Err(invalid_memory_id_error(raw, err));
                }
            }
        };
        if !first {
            println!();
        }
        first = false;
        print_chunk(&loaded.memory.reader, &loaded.memory.facts, chunk_id)?;
    }
    Ok(())
}

fn cmd_migrate_legacy(storage: MemoryStorage<'_>) -> Result<()> {
    // Migration deliberately freezes and closes the old repository first,
    // then performs preflight, publication, and verification through one
    // native target open. No legacy pin is changed or consumed.
    let source = freeze_source(storage.pile).context("freeze legacy Memory source")?;
    let plan = memory_cutover::plan(&source)?;
    let published = memory_cutover::publish(&source, &plan, storage.pile, storage.key)?;
    let report = plan.report();
    println!(
        "migrated {} authored Memory commit{}: {} preserved facts + {} canonical shadow facts = {} total planned facts in scope {:X}",
        published.len(),
        if published.len() == 1 { "" } else { "s" },
        report.preserved_facts,
        report.canonical_facts,
        report.output_facts,
        MEMORY_SCOPE_ID,
    );
    println!(
        "{} intrinsic nodes, {} legacy aliases, {} byte-exact cross-scope reference{}; legacy branch retained",
        report.canonical_nodes,
        report.legacy_aliases,
        report.cross_scope_references,
        if report.cross_scope_references == 1 { "" } else { "s" },
    );
    if report.omitted_search_entities != 0 || report.omitted_embedding_facts != 0 {
        println!(
            "preserved {} historical search-index entit{} and {} embedding fact{} as exact legacy exhaust; neither enters the canonical Memory projection",
            report.omitted_search_entities,
            if report.omitted_search_entities == 1 { "y" } else { "ies" },
            report.omitted_embedding_facts,
            if report.omitted_embedding_facts == 1 { "" } else { "s" },
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// create subcommand
// ---------------------------------------------------------------------------

fn cmd_create(storage: MemoryStorage<'_>, args: &[String]) -> Result<()> {
    // A help flag must never be minted as memory content — print usage and stop
    // before any parsing, so `memory create --help` explains itself instead of
    // storing the literal "--help" as a chunk.
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "usage: memory create [--lens <theme>] [<from>..<to>] <summary...>\n\
             \n\
             Create a memory chunk and store it in the pile.\n\
             An optional time range as the first argument grounds the memory in\n\
             that period; without it, defaults to now. --lens <theme> files the\n\
             chunk as a thematic memory kept out of the chronological spine."
        );
        return Ok(());
    }
    if args.is_empty() {
        bail!(
            "usage: memory create [<from>..<to>] <summary...>\n\
             \n\
             Create a memory chunk and store it in the pile.\n\
             An optional time range as the first argument grounds the\n\
             memory in that period. Without it, defaults to now.\n\
             References in prose: (memory:<from>..<to>) is a soft temporal\n\
             address, resolved by range query at read time, no fact minted.\n\
             [why it matters](memory:<hex>) is a hard reference to an exact\n\
             chunk, extracted into a queryable ctx::reference fact. Neither\n\
             affects the span or the hierarchy: containment relates chunks,\n\
             and the explicit range argument always wins."
        );
    }

    // Pull an optional `--lens <theme>` out first: a lens chunk is a thematic
    // memory (e.g. "us", "becoming-self"), kept OUT of the chronological spine.
    let mut lens: Option<String> = None;
    let mut filtered: Vec<String> = Vec::new();
    {
        let mut i = 0;
        while i < args.len() {
            if args[i] == "--lens" && i + 1 < args.len() {
                lens = Some(args[i + 1].clone());
                i += 2;
            } else {
                filtered.push(args[i].clone());
                i += 1;
            }
        }
    }
    let args = &filtered[..];
    if args.is_empty() {
        bail!(
            "summary text is required: memory create [--lens <theme>] [<from>..<to>] <summary...>"
        );
    }

    // If the first argument looks like a time range, parse it.
    let mut explicit_range: Option<(Epoch, Epoch)> = None;
    let summary_start_idx;
    if args[0].contains("..") {
        if let Ok(range) = parse_time_range(&args[0]) {
            explicit_range = Some(range);
            summary_start_idx = 1;
        } else {
            summary_start_idx = 0;
        }
    } else {
        summary_start_idx = 0;
    }

    // A single summary token may reference a file or stdin via the shared `@`
    // convention (`@-`, `@path`, `@@literal`); multiple tokens are a literal
    // space-joined summary, so every existing inline usage is unchanged. This
    // closes the footgun where `@- <<HEREDOC` silently stored the string "@-".
    let summary_tokens = &args[summary_start_idx..];
    let summary_text: String = if summary_tokens.len() == 1 {
        faculties::text_arg(&summary_tokens[0], "summary")?
    } else {
        summary_tokens.join(" ")
    };
    if summary_text.is_empty() {
        bail!("summary text is required: memory create [<from>..<to>] <summary...>");
    }

    let range = match explicit_range {
        Some(range) => range,
        None => {
            let now =
                Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0));
            (now, now)
        }
    };
    let loaded = storage.load()?;
    let chunk_id = create_chunk(
        storage,
        &loaded,
        &summary_text,
        range,
        lens.as_deref(),
        range.1,
    )?;
    println!("range: {}", format_time_range(range.0, range.1));
    println!("id: {chunk_id:x}");
    Ok(())
}

/// The chunk-creation core, shared by `create` and `consolidate`.
///
/// Hard references `[context](memory:<hex>)` in the summary become
/// ctx::reference facts (resolved against the catalog so a dangling hard ref
/// fails at write time). Soft references `(memory:<from>..<to>)` stay prose.
/// Neither affects the span: temporal containment is the only hierarchy, and
/// the given range is stored as typed. Chunks carry no persona or author —
/// the memory belongs to the one being; only cursors are session-scoped.
fn create_chunk(
    storage: MemoryStorage<'_>,
    loaded: &LoadedMemory,
    summary_text: &str,
    range: (Epoch, Epoch),
    lens: Option<&str>,
    observed_at: Epoch,
) -> Result<Id> {
    let hard_refs = scan_hard_references(summary_text);
    let mut reference_ids = BTreeSet::new();
    for hex in &hard_refs {
        let target = resolve_chunk_id(loaded, hex)
            .map_err(|e| anyhow!("hard reference (memory:{hex}): {e}"))?;
        reference_ids.insert(target);
    }

    let start_at: Inline<NsTAIInterval> = (range.0, range.0).try_to_inline().unwrap();
    let end_at: Inline<NsTAIInterval> = (range.1, range.1).try_to_inline().unwrap();
    let observed_at: Inline<NsTAIInterval> = (observed_at, observed_at).try_to_inline().unwrap();
    let (fragment, chunk_id) = memory_model::chunk_fragment(memory_model::ChunkDraft {
        content: memory_model::ChunkDraftContent::Text(summary_text.to_owned()),
        start_at,
        end_at,
        lens: lens.map(str::to_owned),
        references: reference_ids,
        about_exec_result: None,
        about_archive_message: None,
        predecessors: BTreeSet::new(),
        observed_at: BTreeSet::from([observed_at]),
        aliases: BTreeSet::new(),
    })?;
    storage.publish_memory(loaded, fragment)?;
    Ok(chunk_id)
}

// ---------------------------------------------------------------------------
// image subcommand — a WORDLESS memory at a time-coordinate
// ---------------------------------------------------------------------------

/// `memory image <when> <image-path>` — create an image memory chunk. It is
/// JUST a chunk (tag KIND_CHUNK_ID) whose content is a picture instead of prose:
/// no `ctx::summary`, the image bytes live on `ctx::image`. Same time-coordinate
/// as any chunk — `<when>` is a single `YYYY-MM-DDTHH:MM:SS` point (start==end)
/// or a `from..to` range. Embed it into the shared 768-d nomic space with
/// `memory embed` (via nomic-VISION, co-embedded with nomic-text), and it ranks
/// in `memory similar` by MEANING beside text memories. Reference it from prose
/// like any chunk: `[caption](memory:<hex>)`.
fn cmd_image(storage: MemoryStorage<'_>, args: &[String]) -> Result<()> {
    if args.len() != 2 {
        bail!(
            "usage: memory image <when> <image-path>\n\
             \n\
             Create a WORDLESS image memory chunk and store it in the pile.\n\
             <when> is a single TAI timestamp (YYYY-MM-DDTHH:MM:SS — a point\n\
             where start==end) or a `from..to` range. The image bytes are stored\n\
             as a blob; embed it into the shared nomic space with `memory embed`\n\
             (nomic-VISION-768), and it ranks in `memory similar` by meaning\n\
             beside text memories. Reference it from prose with [caption](memory:<hex>)."
        );
    }
    let when = &args[0];
    let image_path = Path::new(&args[1]);
    let range = if when.contains("..") {
        parse_time_range(when)?
    } else {
        let p = parse_tai_timestamp(when)?;
        (p, p)
    };
    let bytes = std::fs::read(image_path)
        .with_context(|| format!("read image {}", image_path.display()))?;
    if bytes.is_empty() {
        bail!("image file is empty: {}", image_path.display());
    }

    let loaded = storage.load()?;
    let chunk_id = create_image_chunk(storage, &loaded, &bytes, range)?;
    println!("range: {}", format_time_range(range.0, range.1));
    println!("id: {chunk_id:x}");
    println!(
        "({} image bytes stored; run `memory embed` to place it in the shared nomic space)",
        bytes.len()
    );
    Ok(())
}

/// Store image bytes as a blob and create a wordless image chunk at `range`.
/// Mirrors `create_chunk`, but the content is the picture (`ctx::image`) rather
/// than a summary — temporal containment (the only hierarchy) still relates it
/// to text chunks by time, and `[caption](memory:<hex>)` references still point
/// at it like any chunk.
fn create_image_chunk(
    storage: MemoryStorage<'_>,
    loaded: &LoadedMemory,
    bytes: &[u8],
    range: (Epoch, Epoch),
) -> Result<Id> {
    let start_at: Inline<NsTAIInterval> = (range.0, range.0).try_to_inline().unwrap();
    let end_at: Inline<NsTAIInterval> = (range.1, range.1).try_to_inline().unwrap();
    let observed_at: Inline<NsTAIInterval> = (range.1, range.1).try_to_inline().unwrap();
    let (fragment, chunk_id) = memory_model::chunk_fragment(memory_model::ChunkDraft {
        content: memory_model::ChunkDraftContent::Image(bytes.to_vec()),
        start_at,
        end_at,
        lens: None,
        references: BTreeSet::new(),
        about_exec_result: None,
        about_archive_message: None,
        predecessors: BTreeSet::new(),
        observed_at: BTreeSet::from([observed_at]),
        aliases: BTreeSet::new(),
    })?;
    storage.publish_memory(loaded, fragment)?;
    Ok(chunk_id)
}

// ---------------------------------------------------------------------------
// consolidate + replay — the comb verbs
// ---------------------------------------------------------------------------

const CONSOLIDATE_STREAM: &str = "consolidate-edge";
const MEMORY_REPLAY_STREAM: &str = "memory-replay";

fn comb_persona() -> Result<String> {
    std::env::var("PERSONA").map_err(|_| {
        anyhow!(
            "no persona: set $PERSONA.\n\
             Cursors are session bookkeeping — no agent is defaulted as \
             \"the\" rememberer; the memories themselves belong to the one \
             enduring memory stream and are never persona-scoped."
        )
    })
}

fn comb_advance(
    storage: MemoryStorage<'_>,
    loaded: &LoadedComb,
    stream: &str,
    persona: &str,
    position: Option<Epoch>,
    grain: Option<&str>,
) -> Result<()> {
    let now = Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0));
    let position = position.map(|value| (value, value).try_to_inline().unwrap());
    let observed_at = (now, now).try_to_inline().unwrap();
    let predecessors = loaded
        .comb_catalog
        .resolution(stream, persona)
        .map(comb_model::CursorResolution::head_ids)
        .unwrap_or_default()
        .into_iter()
        .collect();
    let (fragment, _) = comb_model::cursor_fragment(comb_model::CursorDraft {
        stream: stream.to_owned(),
        persona: persona.to_owned(),
        position,
        grain: grain.map(str::to_owned),
        predecessors,
        observed_at: BTreeSet::from([observed_at]),
    })?;
    storage.publish_comb(loaded, fragment)
}

/// `memory consolidate start <ts> | stop | <ts> <summary...>`
///
/// The consolidation edge is where the next chunk opens. `<ts> <summary>`
/// writes a chunk spanning [edge, ts] and advances the edge to ts — the
/// boundary is chosen in hindsight (you pass the timestamp where the shift
/// happened, typically copied from replay output; the shift-signaling
/// message becomes the next chunk's opening).
fn cmd_consolidate(storage: MemoryStorage<'_>, args: &[String]) -> Result<()> {
    let persona = comb_persona()?;
    if args.is_empty() {
        bail!(
            "usage: memory consolidate start <YYYY-MM-DDTHH:MM:SS>\n\
             \x20      memory consolidate stop\n\
             \x20      memory consolidate <YYYY-MM-DDTHH:MM:SS> <summary...>"
        );
    }
    let loaded = storage.load_comb()?;
    match args[0].as_str() {
        "start" => {
            let Some(raw) = args.get(1) else {
                bail!("usage: memory consolidate start <YYYY-MM-DDTHH:MM:SS>");
            };
            let edge = parse_tai_timestamp(raw)?;
            comb_advance(
                storage,
                &loaded,
                CONSOLIDATE_STREAM,
                &persona,
                Some(edge),
                None,
            )?;
            println!("consolidation edge set to {raw} (persona {persona})");
            Ok(())
        }
        "stop" => {
            comb_advance(storage, &loaded, CONSOLIDATE_STREAM, &persona, None, None)?;
            println!("consolidation stopped (persona {persona})");
            Ok(())
        }
        _ => {
            let until = parse_tai_timestamp(&args[0])?;
            let summary = args[1..].join(" ");
            if summary.is_empty() {
                bail!("summary required: memory consolidate <ts> <summary...>");
            }
            let Some(resolution) = loaded.comb_catalog.resolution(CONSOLIDATE_STREAM, &persona)
            else {
                bail!(
                    "no open consolidation edge for persona {persona}: \
                         use `memory consolidate start <ts>`"
                );
            };
            let state = resolution.settled_state()?;
            let Some(position) = state.position else {
                bail!(
                    "no open consolidation edge for persona {persona}: \
                         use `memory consolidate start <ts>`"
                );
            };
            let edge_key = interval_key(position);
            let edge = key_to_epoch(edge_key);
            if until.to_tai_duration().total_nanoseconds() <= edge_key {
                bail!(
                    "consolidate target {} is not after the open edge {}",
                    args[0],
                    fmt_epoch(edge)
                );
            }
            // The boundary timestamp is a deterministic observation for
            // this automatic write, so retrying a half-completed
            // Memory-then-Comb publication yields the same Memory data.
            let chunk_id = create_chunk(
                storage,
                &loaded.memory,
                &summary,
                (edge, until),
                None,
                until,
            )?;
            comb_advance(
                storage,
                &loaded,
                CONSOLIDATE_STREAM,
                &persona,
                Some(until),
                None,
            )?;
            println!("range: {}", format_time_range(edge, until));
            println!("id: {chunk_id:x}");
            println!("edge → {}", args[0]);
            Ok(())
        }
    }
}

/// Parse a grain like "90m", "2h", "1d", "4w" into nanoseconds.
fn parse_grain(s: &str) -> Result<i128> {
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: i128 = num.parse().with_context(|| format!("invalid grain: {s}"))?;
    let ns_per = match unit {
        "m" => 60_i128 * 1_000_000_000,
        "h" => 3_600_i128 * 1_000_000_000,
        "d" => 86_400_i128 * 1_000_000_000,
        "w" => 7 * 86_400_i128 * 1_000_000_000,
        _ => bail!("grain unit must be m/h/d/w: {s}"),
    };
    Ok(n * ns_per)
}

/// Preserve a replay time-coordinate as the atomic batch boundary.  A caller
/// asking for `requested` rows gets at least that many, plus every remaining
/// row with the same start coordinate as the nominal final row.
fn replay_take_count(batch: &[(i128, i128, Id)], requested: usize) -> usize {
    if requested == 0 || batch.is_empty() {
        return 0;
    }
    let nominal_take = requested.min(batch.len());
    let boundary_start = batch[nominal_take - 1].0;
    batch
        .iter()
        .take_while(|(start, _, _)| *start <= boundary_start)
        .count()
}

/// `memory replay start <grain> [<from>] | stop | [<count>]`
///
/// Streams the memory itself, chronologically, at a zoom level: maximal
/// non-superseded chunks whose span-width fits the grain. This is how upper
/// layers get written — replay the layer below, consolidate up. Reads ALL
/// chunks regardless of which session wrote them: one being, one memory.
fn cmd_replay(storage: MemoryStorage<'_>, args: &[String]) -> Result<()> {
    let persona = comb_persona()?;
    let loaded = storage.load_comb()?;
    match args.first().map(String::as_str) {
        Some("start") => {
            let Some(grain_raw) = args.get(1) else {
                bail!("usage: memory replay start <grain e.g. 2h/1d/4w> [<from-ts>]");
            };
            parse_grain(grain_raw)?;
            let from = match args.get(2) {
                Some(raw) => parse_tai_timestamp(raw)?,
                None => Epoch::from_gregorian_tai(1970, 1, 1, 0, 0, 0, 0),
            };
            let position = from - hifitime::Duration::from_total_nanoseconds(1);
            comb_advance(
                storage,
                &loaded,
                MEMORY_REPLAY_STREAM,
                &persona,
                Some(position),
                Some(grain_raw),
            )?;
            println!("memory replay started at grain {grain_raw} (persona {persona})");
            Ok(())
        }
        Some("stop") => {
            comb_advance(storage, &loaded, MEMORY_REPLAY_STREAM, &persona, None, None)?;
            println!("memory replay stopped (persona {persona})");
            Ok(())
        }
        other => {
            let count: usize = match other {
                None => 5,
                Some(raw) => raw
                    .parse()
                    .with_context(|| format!("expected a batch count, got `{raw}`"))?,
            };
            if count == 0 {
                bail!("memory replay batch count must be greater than zero");
            }
            let Some(resolution) = loaded
                .comb_catalog
                .resolution(MEMORY_REPLAY_STREAM, &persona)
            else {
                bail!(
                    "no active memory replay for persona {persona}: \
                         use `memory replay start <grain> [<from>]`"
                );
            };
            let state = resolution.settled_state()?;
            let (Some(position), Some(grain_raw)) = (state.position, state.grain.as_deref()) else {
                bail!(
                    "no active memory replay for persona {persona}: \
                         use `memory replay start <grain> [<from>]`"
                );
            };
            let position_key = interval_key(position);
            let grain_ns = parse_grain(grain_raw)?;
            let space = &loaded.memory.memory.facts;

            // Chunks at this zoom: width fits the grain, not superseded,
            // and maximal among grain-fitting chunks (not contained in a
            // wider one that also fits — that one IS this zoom's voice).
            let mut fitting: Vec<(i128, i128, Id)> = Vec::new();
            for chunk_id in loaded.memory.catalog.live_chunk_ids() {
                let (Some(s), Some(e)) = (
                    chunk_start_at(space, chunk_id),
                    chunk_end_at(space, chunk_id),
                ) else {
                    continue;
                };
                let (sk, ek) = (interval_key(s), interval_key(e));
                if ek - sk <= grain_ns {
                    fitting.push((sk, ek, chunk_id));
                }
            }
            let maximal: Vec<(i128, i128, Id)> = fitting
                .iter()
                .filter(|(sk, ek, id)| {
                    !fitting.iter().any(|(osk, oek, oid)| {
                        oid != id && osk <= sk && oek >= ek && (oek - osk) > (ek - sk)
                    })
                })
                .copied()
                .collect();

            let mut batch: Vec<(i128, i128, Id)> = maximal
                .into_iter()
                .filter(|(sk, _, _)| *sk > position_key)
                .collect();
            batch.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
            let total = batch.len();
            if total == 0 {
                println!("memory replay complete at grain {grain_raw}: nothing after the cursor.");
                return Ok(());
            }
            let take = replay_take_count(&batch, count);
            let mut last_start = position_key;
            for (sk, ek, chunk_id) in batch.iter().take(take) {
                let summary = match chunk_summary_handle(space, *chunk_id) {
                    Some(handle) => {
                        let view: View<str> = loaded
                            .memory
                            .memory
                            .reader
                            .get(handle)
                            .context("read chunk summary")?;
                        view.trim_end().to_string()
                    }
                    None => String::new(),
                };
                println!(
                    "── {} ({:x})",
                    format_time_range(key_to_epoch(*sk), key_to_epoch(*ek)),
                    chunk_id
                );
                println!("{summary}");
                println!();
                last_start = *sk;
            }
            comb_advance(
                storage,
                &loaded,
                MEMORY_REPLAY_STREAM,
                &persona,
                Some(key_to_epoch(last_start)),
                Some(grain_raw),
            )?;
            println!(
                "— batch: {take} chunk(s) at grain {grain_raw}; {} remaining",
                total - take
            );
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// supersede subcommand
// ---------------------------------------------------------------------------

fn point_now() -> Inline<NsTAIInterval> {
    let now = Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0));
    (now, now).try_to_inline().unwrap()
}

fn chunk_draft_from_row(
    loaded: &LoadedMemory,
    row: &memory_model::ChunkRow,
    start_at: Inline<NsTAIInterval>,
    end_at: Inline<NsTAIInterval>,
    predecessors: BTreeSet<Id>,
) -> Result<memory_model::ChunkDraft> {
    let content = match row.content {
        memory_model::ChunkContent::Text(handle) => memory_model::ChunkDraftContent::Text(
            memory_model::read_text(&loaded.memory.reader, handle)
                .with_context(|| format!("read Memory chunk {:x} summary", row.id))?,
        ),
        memory_model::ChunkContent::Image(handle) => memory_model::ChunkDraftContent::Image(
            memory_model::read_image(&loaded.memory.reader, handle)
                .with_context(|| format!("read Memory chunk {:x} image", row.id))?
                .to_vec(),
        ),
    };
    let lens = row
        .lens
        .map(|handle| memory_model::read_text(&loaded.memory.reader, handle))
        .transpose()
        .with_context(|| format!("read Memory chunk {:x} lens", row.id))?;
    Ok(memory_model::ChunkDraft {
        content,
        start_at,
        end_at,
        lens,
        references: row.references.clone(),
        about_exec_result: row.about_exec_result,
        about_archive_message: row.about_archive_message,
        predecessors,
        observed_at: BTreeSet::from([point_now()]),
        aliases: BTreeSet::new(),
    })
}

fn descends_from(catalog: &memory_model::MemoryCatalog, node: Id, ancestor: Id) -> bool {
    let mut pending = vec![node];
    let mut seen = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if !seen.insert(current) {
            continue;
        }
        let predecessors = catalog
            .chunks
            .get(&current)
            .map(|row| &row.predecessors)
            .or_else(|| {
                catalog
                    .retractions
                    .get(&current)
                    .map(|row| &row.predecessors)
            });
        for predecessor in predecessors.into_iter().flatten() {
            if *predecessor == ancestor {
                return true;
            }
            pending.push(*predecessor);
        }
    }
    false
}

/// Reconcile two revisions by copying `new`'s complete state into a fresh
/// intrinsic join which names both histories. If `new` already contains
/// `old` in its ancestry the operation is already satisfied and is a no-op.
fn cmd_supersede(storage: MemoryStorage<'_>, args: &[String]) -> Result<()> {
    if args.len() != 2 {
        bail!("usage: memory supersede <new-id> <old-id>");
    }
    let loaded = storage.load()?;
    let new =
        resolve_chunk_id(&loaded, &args[0]).map_err(|e| anyhow!("new chunk {}: {e}", args[0]))?;
    let old =
        resolve_chunk_id(&loaded, &args[1]).map_err(|e| anyhow!("old chunk {}: {e}", args[1]))?;
    if new == old || descends_from(&loaded.catalog, new, old) {
        println!("{new:x} already descends from {old:x}; no change");
        return Ok(());
    }
    if descends_from(&loaded.catalog, old, new) {
        bail!(
            "old chunk {old:x} already descends from new chunk {new:x}; \
             refusing a backwards reconciliation"
        );
    }
    let row = &loaded.catalog.chunks[&new];
    let draft = chunk_draft_from_row(
        &loaded,
        row,
        row.start_at,
        row.end_at,
        BTreeSet::from([new, old]),
    )?;
    let (fragment, joined) = memory_model::chunk_fragment(draft)?;
    storage.publish_memory(&loaded, fragment)?;
    println!("{joined:x} joins {new:x} and {old:x}");
    Ok(())
}

// ---------------------------------------------------------------------------
// retract subcommand
// ---------------------------------------------------------------------------

/// Retire a chunk with NO replacement. Mints a *retraction* tombstone: a fresh
/// entity tagged `KIND_RETRACTION` (never `KIND_CHUNK_ID`, so it never
/// enumerates as a chunk) carrying the `supersedes` edge, plus the reason as
/// its `ctx::summary` when one is given. The target leaves every view; the
/// retraction stays invisible to covers/trees/recall yet queryable as a class
/// ("what have I walked back, and why"). Use this for mistaken/duplicate
/// ingests, where `supersede` would otherwise force a bogus replacement chunk
/// that then shows up as a memory of its own. Nothing is destroyed: the retired
/// chunk's own facts survive for direct-id / provenance lookup.
fn cmd_retract(storage: MemoryStorage<'_>, args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("usage: memory retract <id> [reason...]");
    }
    let reason = args[1..].join(" ");
    let loaded = storage.load()?;
    let old = resolve_chunk_id(&loaded, &args[0]).map_err(|e| anyhow!("chunk {}: {e}", args[0]))?;
    let (fragment, retraction) =
        memory_model::retraction_fragment(memory_model::RetractionDraft {
            reason: (!reason.is_empty()).then_some(reason.clone()),
            predecessors: BTreeSet::from([old]),
            observed_at: BTreeSet::from([point_now()]),
        })?;
    storage.publish_memory(&loaded, fragment)?;

    if reason.is_empty() {
        println!("retracted {old:x} (retraction {retraction:x})");
    } else {
        println!("retracted {old:x} — {reason} (retraction {retraction:x})");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// retractions subcommand
// ---------------------------------------------------------------------------

/// Audit surface for `retract`: list every `KIND_RETRACTION` tombstone, the
/// chunk(s) it retracts, and the recorded reason. Retracted chunks are gone from
/// covers/trees/recall but never lost — what was walked back, and why, is always
/// answerable here.
fn cmd_retractions(storage: MemoryStorage<'_>, _args: &[String]) -> Result<()> {
    let loaded = storage.load()?;
    if loaded.catalog.retractions.is_empty() {
        println!("no retractions.");
        return Ok(());
    }
    for row in loaded.catalog.retractions.values() {
        let reason = row
            .reason
            .map(|handle| memory_model::read_text(&loaded.memory.reader, handle))
            .transpose()?
            .unwrap_or_else(|| "(no reason recorded)".to_string());
        println!("retraction {:x} — {reason}", row.id);
        for target in &row.predecessors {
            println!("    -> retracted {target:x}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// respan subcommand
// ---------------------------------------------------------------------------

/// Correct a chunk's time span while preserving every other component of its
/// state: text or image, lens, contextual references, and provenance links.
fn cmd_respan(storage: MemoryStorage<'_>, args: &[String]) -> Result<()> {
    if args.len() != 2 || !args[1].contains("..") {
        bail!(
            "usage: memory respan <id> <from>..<to>\n\
             \n\
             Creates a corrected chunk (same summary, new span) that\n\
             supersedes the old one. Views exclude superseded chunks."
        );
    }
    let (range_start, range_end) = parse_time_range(&args[1])?;

    let loaded = storage.load()?;
    let old = resolve_chunk_id(&loaded, &args[0]).map_err(|e| anyhow!("chunk {}: {e}", args[0]))?;
    let row = &loaded.catalog.chunks[&old];
    let start_at: Inline<NsTAIInterval> = (range_start, range_start).try_to_inline().unwrap();
    let end_at: Inline<NsTAIInterval> = (range_end, range_end).try_to_inline().unwrap();
    let draft = chunk_draft_from_row(&loaded, row, start_at, end_at, BTreeSet::from([old]))?;
    let (fragment, new_chunk) = memory_model::chunk_fragment(draft)?;
    storage.publish_memory(&loaded, fragment)?;

    println!("range: {}", format_time_range(range_start, range_end));
    println!("id: {new_chunk:x} (supersedes {old:x})");
    Ok(())
}

// ---------------------------------------------------------------------------
// meta subcommand
// ---------------------------------------------------------------------------

/// Humanize a nanosecond duration into a coarse `d/h/m/s` string.
fn humanize_ns(ns: i128) -> String {
    let secs = ns / 1_000_000_000;
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3600;
    let mins = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else if mins > 0 {
        format!("{mins}m")
    } else {
        format!("{secs}s")
    }
}

/// `memory lens [<theme>]` — the thematic weave that runs beside the spine.
/// With no theme: list every lens memory (theme · span · first line). With a
/// theme substring: print the full text of the matching lens narratives. Lens
/// chunks are deliberately outside the temporal cover, so they can overlap each
/// other and the spine freely.
fn cmd_lens(storage: MemoryStorage<'_>, args: &[String]) -> Result<()> {
    let filter = args.first().map(|s| s.to_lowercase());
    let loaded = storage.load()?;
    let space = &loaded.memory.facts;
    let mut lenses: Vec<(String, i128, i128, Id)> = Vec::new();
    for id in loaded.catalog.live_chunk_ids() {
        let Some(lh) = chunk_lens_handle(space, id) else {
            continue;
        };
        let theme: String = loaded
            .memory
            .reader
            .get::<View<str>, LongString>(lh)
            .context("read lens theme")?
            .as_ref()
            .to_string();
        let (Some(s), Some(e)) = (chunk_start_at(space, id), chunk_end_at(space, id)) else {
            continue;
        };
        lenses.push((theme, interval_key(s), interval_key(e), id));
    }
    if let Some(t) = &filter {
        lenses.retain(|(theme, _, _, _)| theme.to_lowercase().contains(t.as_str()));
    }
    lenses.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    if lenses.is_empty() {
        println!(
            "no lens memories{} — create one with `memory create --lens <theme> <from>..<to> <summary>`",
            filter.map(|t| format!(" matching \"{t}\"")).unwrap_or_default()
        );
        return Ok(());
    }

    if filter.is_some() {
        for (theme, s, e, id) in &lenses {
            println!(
                "\n## [{theme}] {}  ({id:x})",
                format_time_range(key_to_epoch(*s), key_to_epoch(*e))
            );
            if let Some(h) = chunk_summary_handle(space, *id) {
                let summary: View<str> =
                    loaded.memory.reader.get(h).context("read lens summary")?;
                println!("{}", summary.trim_end());
            }
        }
    } else {
        println!("{} lens memor(ies):", lenses.len());
        for (theme, s, e, id) in &lenses {
            let first = chunk_summary_handle(space, *id)
                .and_then(|h| loaded.memory.reader.get::<View<str>, LongString>(h).ok())
                .map(|v| v.as_ref().lines().next().unwrap_or("").to_string())
                .unwrap_or_default();
            println!(
                "  [{theme}] {}  ({id:x})  {first}",
                format_time_range(key_to_epoch(*s), key_to_epoch(*e))
            );
        }
    }
    Ok(())
}

/// `memory list [<grain>]` — show the SHAPE of the memory as time-ranges only,
/// never content (coverage is by time range, not by reference). With a grain,
/// lists the maximal non-superseded chunks whose width fits that zoom — the
/// same layer `replay <grain>` would stream. Without a grain, prints every
/// non-superseded chunk as a containment outline: indentation expresses how
/// wider ranges cover narrower ones.
fn cmd_list(storage: MemoryStorage<'_>, args: &[String]) -> Result<()> {
    let grain: Option<(String, i128)> = match args.first() {
        Some(raw) => Some((raw.clone(), parse_grain(raw)?)),
        None => None,
    };
    let loaded = storage.load()?;
    let mut chunks = collect_chunk_spans(&loaded.memory.facts);
    if chunks.is_empty() {
        println!("no memory chunks");
        return Ok(());
    }

    match grain {
        Some((raw, grain_ns)) => {
            // The layer at this zoom: width <= grain, maximal among fitting
            // (not contained in a wider chunk that also fits) — matches `replay`.
            let fitting: Vec<(i128, i128, Id)> = chunks
                .iter()
                .copied()
                .filter(|(s, e, _)| e - s <= grain_ns)
                .collect();
            let mut layer: Vec<(i128, i128, Id)> = fitting
                .iter()
                .copied()
                .filter(|(s, e, id)| {
                    !fitting
                        .iter()
                        .any(|(os, oe, oid)| oid != id && os <= s && oe >= e && (oe - os) > (e - s))
                })
                .collect();
            layer.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
            println!(
                "layer at grain {raw}: {} chunk(s) of {} total",
                layer.len(),
                chunks.len()
            );
            for (s, e, id) in &layer {
                println!(
                    "  {}  [{}]  ({:x})",
                    format_time_range(key_to_epoch(*s), key_to_epoch(*e)),
                    humanize_ns(e - s),
                    id
                );
            }
        }
        None => {
            // Containment outline: containers before contained; indent by
            // how many strictly-wider chunks contain this one.
            chunks.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
            println!(
                "{} chunk(s) (indent = containment by time range)",
                chunks.len()
            );
            for (s, e, id) in &chunks {
                let depth = chunks
                    .iter()
                    .filter(|(os, oe, oid)| oid != id && os <= s && oe >= e && (oe - os) > (e - s))
                    .count();
                let indent = "  ".repeat(depth + 1);
                println!(
                    "{indent}{}  ({:x})",
                    format_time_range(key_to_epoch(*s), key_to_epoch(*e)),
                    id
                );
            }
        }
    }
    Ok(())
}

/// `memory context [<budget-chars>]` — the antichain cover over ALL of my
/// memories, coarse → fine, fit to a CHARACTER budget. This is the grounding cover a
/// fresh context reads first to wake into its own past: every memory is
/// represented (completeness is invariant), with detail concentrated toward the
/// recent end and the deep past held as coarse summary.
///
/// Unlike the playground — which must degrade silently because the cover
/// *bootstraps* the model and there is no model yet to repair the hierarchy — the
/// faculty is called by an already-running agent. So when even the coarsest cover
/// overflows the budget, it ERRORS with instructions for raising a coarser apex
/// rather than dropping memories: the caller is right there to fix it.
fn cmd_context(storage: MemoryStorage<'_>, args: &[String]) -> Result<()> {
    // Parse `[<budget>] [--chars N] [--about <query words...>]`. The budget is a
    // CHARACTER count: a bare number, `--chars N`, or (as an alias) `--tokens N`
    // all set it directly — there is no separate token estimate anymore (the old
    // estimate ran ~2× off the real token count, which was confusing; characters
    // are exact). `--about` switches the cover from recency-first to
    // relevance-first, concentrating detail on the memories most similar to the
    // query (so a face can be cast with the slice of the past most relevant to
    // its goal).
    let mut budget_chars: usize = 200_000;
    let mut about: Option<String> = None;
    // `--filter <query>` (include-only) and `--remove <query>` (anti-filter) gate
    // ELIGIBILITY by positive similarity to their query; `--sim-threshold <f>` is
    // the shared cosine cutoff (default `DEFAULT_SIM_THRESHOLD`).
    let mut filter_q: Option<String> = None;
    let mut remove_q: Option<String> = None;
    let mut sim_threshold: f32 = DEFAULT_SIM_THRESHOLD;
    // `--chars N` (canonical) / `--tokens N` (alias) name the budget explicitly;
    // when present either wins over the bare positional (a backward-compatible
    // fallback — it also means characters).
    let mut chars_explicit = false;
    {
        // A value flag consumes the following args up to the NEXT recognized flag
        // (or end), so multi-word queries stay unquoted AND `--about`/`--filter`/
        // `--remove` compose in any order.
        let is_flag = |s: &str| {
            matches!(
                s,
                "--about" | "--filter" | "--remove" | "--tokens" | "--chars" | "--sim-threshold"
            )
        };
        let mut i = 0;
        while i < args.len() {
            if matches!(args[i].as_str(), "--about" | "--filter" | "--remove") {
                let mut j = i + 1;
                while j < args.len() && !is_flag(&args[j]) {
                    j += 1;
                }
                let q = args[i + 1..j].join(" ");
                let q = (!q.trim().is_empty()).then_some(q);
                match args[i].as_str() {
                    "--about" => about = q,
                    "--filter" => filter_q = q,
                    _ => remove_q = q,
                }
                i = j;
                continue;
            }
            if args[i] == "--sim-threshold" {
                let raw = args.get(i + 1).ok_or_else(|| {
                    anyhow!("--sim-threshold needs a number in [0,1], e.g. `--sim-threshold 0.55`")
                })?;
                sim_threshold = raw
                    .parse()
                    .map_err(|_| anyhow!("--sim-threshold expects a float, got `{raw}`"))?;
                i += 2;
                continue;
            }
            // `--tokens N` is a backward-compatible ALIAS for `--chars N` (the
            // budget is characters now; there is no separate token path).
            if args[i] == "--tokens" || args[i] == "--chars" {
                let flag = args[i].as_str();
                let raw = args.get(i + 1).ok_or_else(|| {
                    anyhow!("{flag} needs a number, e.g. `memory context --chars 80000`")
                })?;
                budget_chars = raw
                    .parse()
                    .map_err(|_| anyhow!("{flag} expects a positive integer, got `{raw}`"))?;
                chars_explicit = true;
                i += 2;
                continue;
            }
            if !chars_explicit {
                if let Ok(n) = args[i].parse::<usize>() {
                    budget_chars = n;
                }
            }
            i += 1;
        }
    }

    let needs_embeddings = cfg!(feature = "local-embed")
        && (about.is_some() || filter_q.is_some() || remove_q.is_some());
    let loaded = storage.load_context(needs_embeddings)?;
    let cover = build_context_cover(
        &loaded,
        budget_chars,
        about.as_deref(),
        filter_q.as_deref(),
        remove_q.as_deref(),
        sim_threshold,
    )?;
    print!("{cover}");
    Ok(())
}

/// Build the context-cover TEXT — exactly what `memory context` prints to
/// stdout — without printing it. Shared by `cmd_context` (which prints it) and
/// `cover start` (which stores it for cursor-chunked reading), so the cover
/// semantics — antichain completeness, the character budget, the
/// `--about`/`--filter`/`--remove` composition — live in one place and the two
/// callers can never drift. Memory and Embeddings were materialized during
/// the same open-pile read held by `loaded`.
fn build_context_cover(
    loaded: &LoadedContext,
    budget_chars: usize,
    about: Option<&str>,
    filter_q: Option<&str>,
    remove_q: Option<&str>,
    sim_threshold: f32,
) -> Result<String> {
    if collect_chunk_spans(&loaded.memory.memory.facts).is_empty() {
        return Ok("no memory chunks\n".to_string());
    }

    let opts = CoverOpts {
        budget_chars,
        about: about.map(str::to_string),
        filter: filter_q.map(str::to_string),
        remove: remove_q.map(str::to_string),
        sim_threshold,
    };
    faculties::memory_cover::render_cover(
        &loaded.memory.memory.facts,
        &loaded.embeddings.facts,
        &loaded.memory.memory.reader,
        &opts,
    )
}

// ---------------------------------------------------------------------------
// cover subcommand family — cursor-chunked reader over the context cover
// ---------------------------------------------------------------------------
//
// The context cover is too large to ingest in one gulp, so a harness hook can
// force COMPLETE ingestion through a cursor: `cover start` generates the text
// (exactly what `memory context --chars N` prints) and stores it with a zeroed
// cursor; `cover continue` prints the next chunk and advances; `cover status`
// answers "fully ingested?" through its exit code; `cover reset` rewinds
// without regenerating. This is ephemeral harness plumbing, NOT knowledge — it
// must never touch the pile. State lives under
// `${XDG_CACHE_HOME:-$HOME/.cache}/faculties/cover/<session>/` as `cover.txt`
// (the stored cover, byte-exact) plus `cursor.json` (the read offset).

const COVER_DEFAULT_CHARS: usize = 400_000;
/// Default chunk size — sized so a chunk printed to stdout survives
/// tool-result truncation in one piece.
const COVER_DEFAULT_CHUNK_CHARS: usize = 20_000;
const COVER_TEXT_FILE: &str = "cover.txt";
const COVER_CURSOR_FILE: &str = "cursor.json";

/// The cursor half of the cover state: how far `cover continue` has read into
/// the stored cover, in CHARACTERS (the same unit as the context budget — no
/// byte/char ambiguity, and chunk boundaries can never split a multi-byte
/// character).
#[derive(serde::Serialize, serde::Deserialize)]
struct CoverCursor {
    /// Characters of the stored cover already emitted.
    offset: usize,
    /// Chunk size in characters, fixed at `cover start`.
    chunk_chars: usize,
    /// Total characters of the stored cover.
    total_chars: usize,
    /// When the cover was generated (TAI, the clock every chunk uses).
    generated_at: String,
}

/// State directory for one cover session:
/// `${XDG_CACHE_HOME:-$HOME/.cache}/faculties/cover/<key>`. The key becomes a
/// directory name, so path-shaped keys are rejected outright.
fn cover_session_dir(key: &str) -> Result<PathBuf> {
    if key.is_empty() || key == "." || key == ".." || key.contains('/') || key.contains('\\') {
        bail!("invalid session key `{key}` (it becomes a directory name)");
    }
    let base = match std::env::var_os("XDG_CACHE_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => {
            let home = std::env::var_os("HOME")
                .ok_or_else(|| anyhow!("neither XDG_CACHE_HOME nor HOME is set"))?;
            PathBuf::from(home).join(".cache")
        }
    };
    Ok(base.join("faculties").join("cover").join(key))
}

/// How many chunks a cover of `total_chars` splits into at `chunk_chars`.
fn cover_chunk_count(total_chars: usize, chunk_chars: usize) -> usize {
    total_chars.div_ceil(chunk_chars)
}

/// Byte index of the `chars`-th character of `text` (`text.len()` past the
/// end), so chunk slicing lands on character boundaries, never mid-codepoint.
fn cover_byte_of_char(text: &str, chars: usize) -> usize {
    text.char_indices()
        .nth(chars)
        .map(|(byte, _)| byte)
        .unwrap_or(text.len())
}

fn cover_save_cursor(dir: &Path, cursor: &CoverCursor) -> Result<()> {
    let path = dir.join(COVER_CURSOR_FILE);
    let json = serde_json::to_string_pretty(cursor).context("encode cover cursor")?;
    std::fs::write(&path, json).with_context(|| format!("write {}", path.display()))
}

/// Store a freshly generated cover with a zeroed cursor. Returns
/// `(chunk_count, total_chars)`.
fn cover_write_state(
    dir: &Path,
    cover: &str,
    chunk_chars: usize,
    generated_at: String,
) -> Result<(usize, usize)> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("create cover state dir {}", dir.display()))?;
    let text_path = dir.join(COVER_TEXT_FILE);
    std::fs::write(&text_path, cover).with_context(|| format!("write {}", text_path.display()))?;
    let total_chars = cover.chars().count();
    let cursor = CoverCursor {
        offset: 0,
        chunk_chars,
        total_chars,
        generated_at,
    };
    cover_save_cursor(dir, &cursor)?;
    Ok((cover_chunk_count(total_chars, chunk_chars), total_chars))
}

/// Load `(cover text, cursor)` from a session dir; `None` when no cover has
/// been started there.
fn cover_read_state(dir: &Path) -> Result<Option<(String, CoverCursor)>> {
    let text_path = dir.join(COVER_TEXT_FILE);
    let cursor_path = dir.join(COVER_CURSOR_FILE);
    if !text_path.exists() || !cursor_path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&text_path)
        .with_context(|| format!("read {}", text_path.display()))?;
    let raw = std::fs::read_to_string(&cursor_path)
        .with_context(|| format!("read {}", cursor_path.display()))?;
    let cursor: CoverCursor =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", cursor_path.display()))?;
    if cursor.chunk_chars == 0 {
        bail!(
            "corrupt cover cursor {} (chunk_chars is 0) — rerun `memory cover start`",
            cursor_path.display()
        );
    }
    Ok(Some((text, cursor)))
}

/// One `cover continue` step: the emitted chunk with its coordinates, or the
/// already-complete marker. Separated from printing so tests can walk the
/// chunks and prove reassembly equals the stored cover byte-for-byte.
enum CoverStep {
    AlreadyComplete {
        chunks: usize,
    },
    Chunk {
        index: usize,
        chunks: usize,
        start_char: usize,
        end_char: usize,
        text: String,
        complete: bool,
    },
}

/// Advance the cover cursor in `dir` by one chunk and persist the new offset.
fn cover_advance(dir: &Path) -> Result<CoverStep> {
    let Some((text, mut cursor)) = cover_read_state(dir)? else {
        bail!(
            "no cover in {} — run `memory cover start` first",
            dir.display()
        );
    };
    let chunks = cover_chunk_count(cursor.total_chars, cursor.chunk_chars);
    if cursor.offset >= cursor.total_chars {
        return Ok(CoverStep::AlreadyComplete { chunks });
    }
    let start_char = cursor.offset;
    let end_char = (start_char + cursor.chunk_chars).min(cursor.total_chars);
    let chunk = text[cover_byte_of_char(&text, start_char)..cover_byte_of_char(&text, end_char)]
        .to_string();
    cursor.offset = end_char;
    cover_save_cursor(dir, &cursor)?;
    Ok(CoverStep::Chunk {
        index: start_char / cursor.chunk_chars + 1,
        chunks,
        start_char,
        end_char,
        text: chunk,
        complete: end_char >= cursor.total_chars,
    })
}

/// The `cover status` line plus completeness. A missing state reads as an
/// empty, INCOMPLETE cover, so a session-start hook treats "never started" and
/// "not done yet" the same way: block until a start + full walk has happened.
fn cover_status_line(dir: &Path) -> Result<(String, bool)> {
    let Some((_, cursor)) = cover_read_state(dir)? else {
        return Ok(("complete=false loaded=0/0 chars=0/0".to_string(), false));
    };
    let chunks = cover_chunk_count(cursor.total_chars, cursor.chunk_chars);
    let complete = cursor.offset >= cursor.total_chars;
    let loaded = if complete {
        chunks
    } else {
        cursor.offset / cursor.chunk_chars
    };
    Ok((
        format!(
            "complete={complete} loaded={loaded}/{chunks} chars={}/{}",
            cursor.offset, cursor.total_chars
        ),
        complete,
    ))
}

/// Rewind the cursor to 0; the stored cover is untouched (reset never
/// regenerates). Returns the number of chunks now pending.
fn cover_reset_cursor(dir: &Path) -> Result<usize> {
    let Some((_, mut cursor)) = cover_read_state(dir)? else {
        bail!(
            "no cover in {} — run `memory cover start` first",
            dir.display()
        );
    };
    cursor.offset = 0;
    cover_save_cursor(dir, &cursor)?;
    Ok(cover_chunk_count(cursor.total_chars, cursor.chunk_chars))
}

/// `memory cover start|continue|status|reset` — the cursor state machine a
/// harness hook drives to force complete ingestion of the context cover:
/// reset (or start) on session start, block turn-end until `status` exits 0.
fn cmd_cover(storage: MemoryStorage<'_>, args: &[String]) -> Result<()> {
    let usage = "usage: memory cover start [--chars N] [--chunk-chars M] [--session KEY]\n\
                 \x20      memory cover continue [--session KEY]\n\
                 \x20      memory cover status [--session KEY]\n\
                 \x20      memory cover reset [--session KEY]";
    let Some(verb) = args.first().map(String::as_str) else {
        bail!("{usage}");
    };
    if matches!(verb, "--help" | "-h") {
        println!("{usage}");
        return Ok(());
    }
    let mut budget_chars: usize = COVER_DEFAULT_CHARS;
    let mut chunk_chars: usize = COVER_DEFAULT_CHUNK_CHARS;
    let mut session = "default".to_string();
    {
        let mut i = 1;
        while i < args.len() {
            let flag = args[i].as_str();
            match flag {
                "--chars" | "--chunk-chars" | "--session" => {
                    let raw = args
                        .get(i + 1)
                        .ok_or_else(|| anyhow!("{flag} needs a value\n{usage}"))?;
                    match flag {
                        "--session" => session = raw.clone(),
                        _ => {
                            let n: usize = raw.parse().map_err(|_| {
                                anyhow!("{flag} expects a positive integer, got `{raw}`")
                            })?;
                            if n == 0 {
                                bail!("{flag} must be positive");
                            }
                            if flag == "--chars" {
                                budget_chars = n;
                            } else {
                                chunk_chars = n;
                            }
                        }
                    }
                    i += 2;
                }
                other => bail!("unknown argument `{other}`\n{usage}"),
            }
        }
    }
    let dir = cover_session_dir(&session)?;

    match verb {
        "start" => {
            let loaded = storage.load_context(false)?;
            let cover = build_context_cover(
                &loaded,
                budget_chars,
                None,
                None,
                None,
                DEFAULT_SIM_THRESHOLD,
            )?;
            let now =
                Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0));
            let (chunks, total) = cover_write_state(&dir, &cover, chunk_chars, fmt_epoch(now))?;
            println!(
                "cover: generated {chunks} chunks (~{chunk_chars} chars each, {total} chars total); run 'memory cover continue'"
            );
            Ok(())
        }
        "continue" => match cover_advance(&dir)? {
            CoverStep::AlreadyComplete { chunks } => {
                println!("COVER COMPLETE {chunks}/{chunks} (nothing to do)");
                Ok(())
            }
            CoverStep::Chunk {
                index,
                chunks,
                start_char,
                end_char,
                text,
                complete,
            } => {
                println!("COVER CHUNK {index}/{chunks} (chars {start_char}..{end_char})");
                // The chunk itself, verbatim; a bare newline is appended only
                // when the chunk does not end on one, to keep the following
                // line (or the shell prompt) off the chunk's last line. The
                // stored cover is untouched by this — reassembly from state is
                // byte-exact.
                print!("{text}");
                if !text.ends_with('\n') {
                    println!();
                }
                if complete {
                    println!("COVER COMPLETE {chunks}/{chunks}");
                }
                Ok(())
            }
        },
        "status" => {
            let (line, complete) = cover_status_line(&dir)?;
            println!("{line}");
            // Hook-friendly: the exit code IS the answer (0 complete, 1 not).
            if !complete {
                std::process::exit(1);
            }
            Ok(())
        }
        "reset" => {
            let chunks = cover_reset_cursor(&dir)?;
            println!("cover: cursor reset ({chunks} chunks pending)");
            Ok(())
        }
        other => bail!("unknown cover subcommand `{other}`\n{usage}"),
    }
}

/// the fine edge; `check 13w` finds regions with no coarse cover).
fn cmd_check(storage: MemoryStorage<'_>, args: &[String]) -> Result<()> {
    let Some(grain_raw) = args.first() else {
        bail!("usage: memory check <grain e.g. 1d/4w/13w>");
    };
    let grain_ns = parse_grain(grain_raw)?;
    let loaded = storage.load()?;
    let all = collect_chunk_spans(&loaded.memory.facts);
    if all.is_empty() {
        println!("no memory chunks");
        return Ok(());
    }
    let global_start = all.iter().map(|(s, _, _)| *s).min().unwrap();
    let global_end = all.iter().map(|(_, e, _)| *e).max().unwrap();

    // Coverage at this zoom: intervals of chunks with width <= grain.
    let mut covering: Vec<(i128, i128)> = all
        .iter()
        .filter(|(s, e, _)| e - s <= grain_ns)
        .map(|(s, e, _)| (*s, *e))
        .collect();
    covering.sort_by_key(|(s, _)| *s);

    // Sweep for holes in [global_start, global_end].
    let mut gaps: Vec<(i128, i128)> = Vec::new();
    let mut cursor = global_start;
    for (s, e) in &covering {
        if *s > cursor {
            gaps.push((cursor, *s));
        }
        if *e > cursor {
            cursor = *e;
        }
    }
    if cursor < global_end {
        gaps.push((cursor, global_end));
    }
    // A gap only matters at coarseness G if it is at least G wide; smaller
    // holes are below this zoom's resolution (you'd see them at a finer grain).
    gaps.retain(|(s, e)| e - s >= grain_ns);

    println!(
        "extent {}  ({} chunk(s) of width <= {grain_raw})",
        format_time_range(key_to_epoch(global_start), key_to_epoch(global_end)),
        covering.len()
    );
    if gaps.is_empty() {
        println!("OK no gaps >= {grain_raw} — coverage is contiguous at this zoom");
    } else {
        println!("{} gap(s) at grain {grain_raw}:", gaps.len());
        for (s, e) in &gaps {
            println!(
                "  GAP {}  ({})",
                format_time_range(key_to_epoch(*s), key_to_epoch(*e)),
                humanize_ns(e - s)
            );
        }
    }
    Ok(())
}

/// `memory density [<grain>]` — inspection tooling that finds where the
/// containment hierarchy is BUSHY: a span with many direct *leaf* children and
/// no intermediate arc summary combing them into mid-level groups. Bushiness is
/// exactly what makes a cover unable to drill granularly under budget — the only
/// way to add detail beneath a bushy span is to dump ALL its leaves into the
/// cover at once (the lumpy jump), because completeness forbids a partial split.
/// The fix is never to drop memories; it is to ADD intermediate summaries
/// (comb the leaves into arcs). This command only points at where to comb —
/// it writes nothing. Optional `<grain>`: restrict the report to spans of width
/// <= grain (zoom the analysis to e.g. day- vs week-level structure).
fn cmd_density(storage: MemoryStorage<'_>, args: &[String]) -> Result<()> {
    // Threshold for the BUSHY flag: this many direct leaf-children with no
    // intermediate arc make a span expensive to expand in the cover.
    const BUSHY_LEAVES: usize = 5;
    let grain_ns: Option<i128> = match args.first() {
        Some(raw) => Some(parse_grain(raw)?),
        None => None,
    };
    let loaded = storage.load()?;
    let spans = collect_chunk_spans(&loaded.memory.facts);
    if spans.is_empty() {
        println!("no memory chunks");
        return Ok(());
    }
    let n = spans.len();

    // Same containment hierarchy cmd_context builds: a chunk's parent is the
    // tightest strictly-wider chunk that spans it (time-range subsumption).
    let strict_contains = |a: usize, b: usize| -> bool {
        spans[a].0 <= spans[b].0
            && spans[a].1 >= spans[b].1
            && (spans[a].1 - spans[a].0) > (spans[b].1 - spans[b].0)
    };
    let width = |i: usize| spans[i].1 - spans[i].0;
    let mut parent: Vec<Option<usize>> = vec![None; n];
    for (i, parent_slot) in parent.iter_mut().enumerate() {
        let mut best: Option<usize> = None;
        for j in 0..n {
            if j != i && strict_contains(j, i) {
                best = Some(match best {
                    Some(b) if width(b) <= width(j) => b,
                    _ => j,
                });
            }
        }
        *parent_slot = best;
    }
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, parent) in parent.iter().copied().enumerate() {
        if let Some(p) = parent {
            children[p].push(i);
        }
    }

    // Subtree depth (leaves = 0) and size, computed narrow→wide so children
    // are finished before their parent.
    let mut depth = vec![0usize; n];
    let mut subtree = vec![1usize; n];
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|&i| width(i));
    for &i in &order {
        if let Some(p) = parent[i] {
            depth[p] = depth[p].max(depth[i] + 1);
            subtree[p] += subtree[i];
        }
    }
    let leaf_kids = |i: usize| {
        children[i]
            .iter()
            .filter(|&&c| children[c].is_empty())
            .count()
    };

    // Non-leaf spans (forks worth inspecting: >= 2 children), optionally
    // restricted to a coarseness zoom.
    let mut forks: Vec<usize> = (0..n)
        .filter(|&i| children[i].len() >= 2)
        .filter(|&i| grain_ns.is_none_or(|g| width(i) <= g))
        .collect();

    // Classify each fork: BUSHY (many flat leaves, no comb) / coarse (few
    // children) / balanced (the rest — already has intermediate arcs).
    let classify = |i: usize| -> &'static str {
        if leaf_kids(i) >= BUSHY_LEAVES {
            "BUSHY"
        } else if children[i].len() <= 3 {
            "coarse"
        } else {
            "balanced"
        }
    };

    let total_forks = forks.len();
    let bushy_count = forks.iter().filter(|&&i| classify(i) == "BUSHY").count();
    println!(
        "memory density — {n} chunk(s), {total_forks} fork(s) (>=2 children){}",
        grain_ns
            .map(|_| format!(" of width <= {}", args[0]))
            .unwrap_or_default(),
    );
    println!(
            "  BUSHY = >= {BUSHY_LEAVES} direct leaf-children with no intermediate arc (expensive to expand → comb leaves into arcs); {bushy_count} found"
        );
    if forks.is_empty() {
        println!("  (no forks at this zoom)");
        return Ok(());
    }

    // Bushiest first: by direct leaf-children desc, then recency (end) desc.
    // Shallow subtrees with many leaves are the worst — splitting them dumps
    // every leaf into the cover at once.
    forks.sort_by(|&a, &b| {
        leaf_kids(b)
            .cmp(&leaf_kids(a))
            .then(spans[b].1.cmp(&spans[a].1))
    });
    let render = |i: usize| -> String {
        format!(
            "{:8} {}  ({:x})  children={} leaf={} depth={} subtree={}",
            classify(i),
            format_time_range(key_to_epoch(spans[i].0), key_to_epoch(spans[i].1)),
            spans[i].2,
            children[i].len(),
            leaf_kids(i),
            depth[i],
            subtree[i],
        )
    };

    println!("\nBushiest forks (worst first):");
    for &i in forks.iter().take(15) {
        println!("  {}", render(i));
    }

    // The recent edge: forks STARTING in the last 14 days, newest first —
    // local structure at the now-end (today's sessions), where chunks are
    // most likely hanging flat and uncombed. (Start-based, so the 2024-rooted
    // apex — whose own fan-out shows in the worst-first list above — doesn't
    // crowd out the genuinely recent forks here.)
    let newest_end = spans.iter().map(|(_, e, _)| *e).max().unwrap();
    let recent_cutoff = newest_end - parse_grain("2w").unwrap_or(0);
    let mut recent: Vec<usize> = forks
        .iter()
        .copied()
        .filter(|&i| spans[i].0 >= recent_cutoff)
        .collect();
    recent.sort_by(|&a, &b| spans[b].1.cmp(&spans[a].1));
    println!("\nRecent edge (forks starting within 2w, newest first):");
    if recent.is_empty() {
        println!("  (none)");
    } else {
        for &i in &recent {
            println!("  {}", render(i));
        }
    }
    Ok(())
}

fn cmd_meta(storage: MemoryStorage<'_>, args: &[String]) -> Result<()> {
    if args.len() != 1 {
        bail!("usage: memory meta <id>");
    }
    let loaded = storage.load_provenance()?;
    let memory = &loaded.memory;
    let space = &memory.memory.facts;
    let raw = &args[0];
    let chunk_id = if raw.contains("..") {
        let (start, end) = parse_time_range(raw)?;
        find_chunk_by_time_range(space, start, end)
            .ok_or_else(|| anyhow!("no memory covers range {raw}"))?
    } else {
        resolve_chunk_id(memory, raw).map_err(|e| invalid_memory_id_error(raw, e))?
    };

    if let (Some(start_v), Some(end_v)) = (
        chunk_start_at(space, chunk_id),
        chunk_end_at(space, chunk_id),
    ) {
        println!(
            "range: {}",
            format_time_range(epoch_from_interval(start_v), epoch_end_from_interval(end_v))
        );
    }
    println!("id: {chunk_id:x}");
    println!("live: {}", memory.catalog.is_live(chunk_id));
    let row = &memory.catalog.chunks[&chunk_id];
    if !row.predecessors.is_empty() {
        println!(
            "supersedes: {}",
            row.predecessors
                .iter()
                .map(|id| format!("{id:x}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let outgoing = chunk_references(space, chunk_id);
    if !outgoing.is_empty() {
        let refs: Vec<String> = outgoing
            .iter()
            .map(
                |cid| match (chunk_start_at(space, *cid), chunk_end_at(space, *cid)) {
                    (Some(s), Some(e)) => format!(
                        "{} ({:x})",
                        format_time_range(epoch_from_interval(s), epoch_end_from_interval(e)),
                        cid
                    ),
                    _ => format!("{cid:x}"),
                },
            )
            .collect();
        println!("references: {}", refs.join(", "));
    }
    let incoming: Vec<Id> = find!(s: Id, pattern!(space, [{ ?s @ ctx::reference: chunk_id }]))
        .filter(|id| memory.catalog.is_live(*id))
        .collect();
    if !incoming.is_empty() {
        println!(
            "referenced_by: {}",
            incoming
                .iter()
                .map(|id| format!("{id:x}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if let Some(exec_id) = row.about_exec_result {
        println!("about_exec_result: {exec_id:x}");
    }
    if let Some(archive_id) = row.about_archive_message {
        println!("about_archive_message: {archive_id:x}");
        print_archive_meta(&loaded.archive.reader, &loaded.archive.facts, archive_id)?;
    }
    Ok(())
}

fn print_archive_meta(reader: &PileReader, archive: &TribleSet, archive_msg_id: Id) -> Result<()> {
    let mut native_projection = false;
    if let Some((block,)) = find!(
        (block: Id),
        pattern!(archive, [{
            archive_msg_id @ archive_schema::source_projection::projects_to: ?block,
        }])
    )
    .next()
    {
        native_projection = true;
        println!("  projects_to: {block:x}");
    }
    if let Some((author,)) = find!(
        (author: Id),
        pattern!(archive, [{
            archive_msg_id @ archive_schema::source_projection::author: ?author,
        }])
    )
    .next()
    {
        native_projection = true;
        println!("  author: {author:x}");
    }
    if let Some((handle,)) = find!(
        (handle: Inline<Handle<LongString>>),
        pattern!(archive, [{
            archive_msg_id @ archive_schema::source_projection::raw_author: ?handle,
        }])
    )
    .next()
    {
        native_projection = true;
        let value: View<str> = reader.get(handle).context("read Archive raw author")?;
        println!("  raw_author: {}", value.as_ref());
    }
    if let Some((namespace,)) = find!(
        (namespace: Id),
        pattern!(archive, [{
            archive_msg_id @ archive_schema::source_projection::source_namespace: ?namespace,
        }])
    )
    .next()
    {
        native_projection = true;
        println!("  source_namespace: {namespace:x}");
    }
    if let Some((handle,)) = find!(
        (handle: Inline<Handle<LongString>>),
        pattern!(archive, [{
            archive_msg_id @ archive_schema::source_projection::source_locator: ?handle,
        }])
    )
    .next()
    {
        native_projection = true;
        let value: View<str> = reader.get(handle).context("read Archive source locator")?;
        println!("  source_locator: {}", value.as_ref());
    }

    // Additive Archive migration deliberately retains the old message entity
    // id.  A historical Memory link therefore remains meaningful even when it
    // predates the canonical source-projection id and has no remap table.
    if !native_projection {
        if let Some(author) = find!(
            author: Id,
            pattern!(archive, [{ archive_msg_id @ legacy_archive_schema::author: ?author }])
        )
        .next()
        {
            println!("  legacy_author: {author:x}");
        }
        if let Some(handle) = find!(
            handle: Inline<Handle<LongString>>,
            pattern!(archive, [{ archive_msg_id @ legacy_archive_schema::author_name: ?handle }])
        )
        .next()
        {
            let value: View<str> = reader
                .get(handle)
                .context("read legacy Archive author name")?;
            println!("  legacy_author_name: {}", value.as_ref());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// reference notation
// ---------------------------------------------------------------------------
//
// Two reference forms live in summary prose (settled design, restored after
// the 2026-06-12 over-steer; see the practice fragment in the wiki):
//
// - SOFT: `(memory:<from>..<to>)` — a temporal address. Human-readable,
//   machine-recognizable, resolved by range query at read time against
//   whatever the best chunk then is. Deliberately NOT parsed at write time;
//   no fact is minted. Addresses are not links.
//
// - HARD: `[why this matters here](memory:<hex>)` — a contextualised
//   cross-reference to an exact chunk. Extracted at create into a
//   ctx::reference fact: queryable in both directions, pinned forever,
//   zero span effect, zero tree role. The bracket text carries the
//   explanation; a bare reference without context is bad style.
//
// Hierarchy is temporal subsumption only. create() once minted ctx::child
// edges from references and let their union OVERRIDE the typed range; that
// conflation of reference with structure is gone for good.

/// Extract hard references `[text](memory:<hex>)` from summary prose.
/// Returns the hex values; range-form references are soft and stay unparsed.
fn scan_hard_references(text: &str) -> Vec<String> {
    let mut refs = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("](memory:") {
        let after = &rest[start + 9..];
        if let Some(end) = after.find(')') {
            let value = after[..end].trim();
            if !value.is_empty()
                && !value.contains("..")
                && value.chars().all(|c| c.is_ascii_hexdigit())
            {
                refs.push(value.to_string());
            }
        }
        rest = &rest[start + 9..];
    }
    refs
}

/// Extract `[text](faculty:<hex>)` markdown link references from text.
/// Returns (faculty, raw_value) pairs for non-memory faculties.
/// Memory links are handled by `scan_memory_links` instead.
#[allow(dead_code)]
fn extract_references(text: &str) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    let mut rest = text;
    while let Some(paren) = rest.find("](") {
        let after = &rest[paren + 2..];
        let end = after.find(')').unwrap_or(after.len());
        let link = &after[..end];
        if let Some(colon) = link.find(':') {
            let faculty = &link[..colon];
            let value = &link[colon + 1..];
            if !faculty.is_empty()
                && faculty
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                && faculty != "memory"  // memory links handled separately
                && !value.is_empty()
            {
                refs.push((faculty.to_string(), value.to_string()));
            }
        }
        rest = &after[end.min(after.len()).max(1)..];
    }
    refs.sort();
    refs.dedup();
    refs
}

/// Find all canonical Archive source projections whose own timestamp (or the
/// projected block timestamp when source time is absent) falls in the range.
fn find_archive_in_range(
    catalog: &TribleSet,
    query_start: Epoch,
    query_end: Epoch,
) -> Vec<(Id, Inline<NsTAIInterval>)> {
    let qs = query_start.to_tai_duration().total_nanoseconds();
    let qe = query_end.to_tai_duration().total_nanoseconds();
    let projections: BTreeSet<Id> = find!(
        id: Id,
        pattern!(catalog, [{
            ?id @ metadata::tag: &archive_schema::source_projection::KIND,
        }])
    )
    .collect();
    let mut out = Vec::new();
    for id in projections {
        let source_time = find!(
            value: Inline<NsTAIInterval>,
            pattern!(catalog, [{
                id @ archive_schema::source_projection::source_timestamp: ?value,
            }])
        )
        .next();
        let time = source_time.or_else(|| {
            let block = find!(
                value: Id,
                pattern!(catalog, [{
                    id @ archive_schema::source_projection::projects_to: ?value,
                }])
            )
            .next()?;
            find!(
                value: Inline<NsTAIInterval>,
                pattern!(catalog, [{ block @ archive_schema::block::timestamp: ?value }])
            )
            .next()
        });
        let Some(t) = time else {
            continue;
        };
        let k = interval_key(t);
        if k >= qs && k <= qe {
            out.push((id, t, k));
        }
    }
    out.sort_by_key(|(_, _, k)| *k);
    out.into_iter().map(|(id, t, _)| (id, t)).collect()
}

/// Resolve provenance for a memory chunk by time-range query — find all
/// exec results (Cognition collection) and Archive source projections
/// whose timestamps fall within the chunk's `[start_at, end_at]` interval.
/// This is the loose-coupling alternative to chunk-side `about_exec_result`
/// / `about_archive_message` attributes: associations emerge from temporal
/// overlap at read-time, so importing archive data after a chunk was written
/// automatically associates it with that chunk.
fn cmd_provenance(storage: MemoryStorage<'_>, args: &[String]) -> Result<()> {
    let Some(chunk_arg) = args.first() else {
        bail!("usage: memory provenance <chunk-id>");
    };

    let loaded = storage.load_provenance()?;
    let memory_catalog = &loaded.memory.memory.facts;
    let chunk_id = resolve_chunk_id(&loaded.memory, chunk_arg)
        .map_err(|e| anyhow!("resolve chunk id `{chunk_arg}`: {e}"))?;

    let start_at = chunk_start_at(memory_catalog, chunk_id)
        .ok_or_else(|| anyhow!("chunk {chunk_id:x} has no start_at"))?;
    let end_at = chunk_end_at(memory_catalog, chunk_id)
        .ok_or_else(|| anyhow!("chunk {chunk_id:x} has no end_at"))?;
    let (start_epoch, _): (Epoch, Epoch) = start_at.try_from_inline().unwrap();
    let (_, end_epoch): (Epoch, Epoch) = end_at.try_from_inline().unwrap();

    println!("chunk: {chunk_id:x}");
    println!(
        "range: {}..{}",
        fmt_epoch(start_epoch),
        fmt_epoch(end_epoch),
    );

    let execs =
        cognition_model::exec_results_in_range(&loaded.cognition.facts, start_epoch, end_epoch);
    println!("\ncognition exec results in range: {}", execs.len());
    for (id, t) in execs {
        let (epoch, _): (Epoch, Epoch) = t.try_from_inline().unwrap();
        println!("  {id:x}  {}", fmt_epoch(epoch));
    }

    let projections = find_archive_in_range(&loaded.archive.facts, start_epoch, end_epoch);
    println!("\narchive projections in range: {}", projections.len());
    for (id, t) in projections {
        let (epoch, _): (Epoch, Epoch) = t.try_from_inline().unwrap();
        println!("  {id:x}  {}", fmt_epoch(epoch));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// show / turn subcommands
// ---------------------------------------------------------------------------

fn print_chunk(reader: &PileReader, space: &TribleSet, chunk_id: Id) -> Result<()> {
    if let Some(handle) = chunk_summary_handle(space, chunk_id) {
        let summary: View<str> = reader.get(handle).context("read chunk summary")?;
        print!("{}", summary.trim_end());
        println!();
        return Ok(());
    }
    // A wordless image memory has no summary — render a marker rather than
    // crash, and export the blob so a Claude-Code reader can Read it to see it.
    if let Some(h) = chunk_image_handle(space, chunk_id) {
        let span = chunk_span_str(space, chunk_id);
        match materialize_image(reader, chunk_id, h) {
            Ok(path) => println!(
                "[image memory @ {span}] → {} (Read this path to view)",
                path.display()
            ),
            Err(e) => println!("[image memory @ {span}] (image export failed: {e})"),
        }
        return Ok(());
    }
    bail!("chunk {:x} has no summary", chunk_id)
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn resolve_chunk_id(loaded: &LoadedMemory, raw: &str) -> Result<Id> {
    let prefix = normalize_prefix(raw)?;
    let space = &loaded.memory.facts;

    // Intrinsic ids and historical aliases are both stable names for one
    // immutable revision.  Resolve them into target ids before deciding
    // ambiguity, so an intrinsic id that is also recorded as its own alias
    // still denotes one chunk.
    let mut chunk_matches = BTreeSet::new();
    for chunk_id in loaded.catalog.chunks.keys().copied() {
        if id_starts_with(chunk_id, prefix.as_str()) {
            chunk_matches.insert(chunk_id);
        }
    }
    for row in loaded.catalog.chunks.values() {
        if row
            .aliases
            .iter()
            .any(|alias| id_starts_with(*alias, prefix.as_str()))
        {
            chunk_matches.insert(row.id);
        }
    }
    match chunk_matches.len() {
        1 => return Ok(*chunk_matches.first().expect("one chunk match")),
        n if n > 1 => {
            bail!("multiple chunk ids or aliases match prefix '{prefix}' (use a longer prefix)")
        }
        _ => {}
    }

    for chunk_id in all_chunk_ids(space) {
        if let Some(turn_id) = chunk_about_exec_result(space, chunk_id) {
            if id_starts_with(turn_id, prefix.as_str()) {
                bail!("turn id `{prefix}` is not a chunk id; use `memory turn {prefix}`");
            }
        }
    }

    bail!("no chunk id matches prefix '{prefix}'")
}

fn print_turn_facets(reader: &PileReader, space: &TribleSet, raw: &str) -> Result<()> {
    let prefix = normalize_prefix(raw)?;
    let mut turn_matches = Vec::new();
    for chunk_id in all_chunk_ids(space) {
        if let Some(turn_id) = chunk_about_exec_result(space, chunk_id) {
            if id_starts_with(turn_id, prefix.as_str()) {
                turn_matches.push((turn_id, chunk_id));
            }
        }
    }
    if turn_matches.is_empty() {
        bail!("no turn_id matches prefix '{prefix}'");
    }

    turn_matches.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    turn_matches.dedup();

    let first_turn = turn_matches[0].0;
    if turn_matches
        .iter()
        .any(|(turn_id, _)| *turn_id != first_turn)
    {
        bail!("multiple turn_id values match prefix '{prefix}' (use a longer prefix)");
    }

    let mut chunk_ids: Vec<Id> = turn_matches.iter().map(|(_, cid)| *cid).collect();
    chunk_ids.sort_unstable_by(|a, b| {
        let a_width = chunk_end_at(space, *a)
            .map(|v| {
                epoch_end_from_interval(v)
                    .to_tai_duration()
                    .total_nanoseconds()
            })
            .unwrap_or(0)
            - chunk_start_at(space, *a)
                .map(|v| epoch_from_interval(v).to_tai_duration().total_nanoseconds())
                .unwrap_or(0);
        let b_width = chunk_end_at(space, *b)
            .map(|v| {
                epoch_end_from_interval(v)
                    .to_tai_duration()
                    .total_nanoseconds()
            })
            .unwrap_or(0)
            - chunk_start_at(space, *b)
                .map(|v| epoch_from_interval(v).to_tai_duration().total_nanoseconds())
                .unwrap_or(0);
        a_width.cmp(&b_width).then(a.cmp(b))
    });

    println!(
        "turn {} has {} memory facet(s)",
        fmt_id(first_turn),
        chunk_ids.len()
    );
    for (i, chunk_id) in chunk_ids.iter().enumerate() {
        if i > 0 {
            println!();
        }
        print_chunk(reader, space, *chunk_id)?;
    }

    Ok(())
}

fn invalid_memory_id_error(raw: &str, cause: anyhow::Error) -> anyhow::Error {
    anyhow!(
        "memory lookup failed for id `{raw}`: {cause}\n\
         hint: that id is wrong here.\n\
         hint: only call `memory <id>` when you want to inspect an id that already appeared in prior output.\n\
         hint: do not guess memory ids or loop lookups; switch to a concrete non-memory action if no valid id is available."
    )
}

// ---------------------------------------------------------------------------
// utilities
// ---------------------------------------------------------------------------

fn normalize_prefix(raw: &str) -> Result<String> {
    let mut prefix = raw.trim().to_ascii_lowercase();
    if let Some(rest) = prefix.strip_prefix("0x") {
        prefix = rest.to_string();
    }
    if prefix.is_empty() {
        bail!("id prefix is empty");
    }
    Ok(prefix)
}

fn id_starts_with(id: Id, prefix: &str) -> bool {
    format!("{id:x}").starts_with(prefix)
}

/// Export an image memory's blob to a temp file and return the path. The
/// Claude-Code environment can't auto-inject pile blobs — a reader has to call
/// the Read tool on a file path — so when a wordless image memory surfaces we
/// drop its bytes at `/tmp/mem_img/<hex>.<ext>` and print the path. No embedder
/// needed; this is pure blob → disk. Extension is sniffed from the magic bytes.
fn materialize_image(
    reader: &PileReader,
    chunk_id: Id,
    handle: Inline<Handle<RawBytes>>,
) -> Result<PathBuf> {
    let bytes: Bytes = reader.get(handle).context("read image bytes")?;
    let b = bytes.as_ref();
    let dir = Path::new("/tmp/mem_img");
    std::fs::create_dir_all(dir).context("create /tmp/mem_img")?;
    let path = dir.join(format!("{chunk_id:x}.{}", sniff_image_ext(b)));
    std::fs::write(&path, b).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// Guess a file extension from an image's leading magic bytes; default `png`.
fn sniff_image_ext(b: &[u8]) -> &'static str {
    if b.starts_with(&[0x89, b'P', b'N', b'G']) {
        "png"
    } else if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        "jpg"
    } else if b.starts_with(b"GIF8") {
        "gif"
    } else if b.len() >= 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        "webp"
    } else if b.starts_with(b"BM") {
        "bmp"
    } else {
        "png"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    use ed25519_dalek::SigningKey;
    use triblespace::core::repo::Repository;

    struct TestPile {
        pile: PathBuf,
        key: PathBuf,
    }

    impl TestPile {
        fn new() -> Self {
            let pile =
                std::env::temp_dir().join(format!("faculties-memory-cover-{}.pile", ufoid().id));
            let key = pile.with_extension("key");
            File::create(&pile).expect("create test pile");
            faculties::collection_cutover::initialize_signer(&pile, Some(&key))
                .expect("initialize test signer");
            Self { pile, key }
        }

        fn storage(&self) -> MemoryStorage<'_> {
            MemoryStorage {
                pile: &self.pile,
                key: Some(&self.key),
            }
        }
    }

    impl Drop for TestPile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.pile);
            let _ = std::fs::remove_file(&self.key);
        }
    }

    fn point(raw: &str) -> Inline<NsTAIInterval> {
        let epoch = parse_tai_timestamp(raw).unwrap();
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn publish_chunk(storage: MemoryStorage<'_>, draft: memory_model::ChunkDraft) -> Id {
        let loaded = storage.load().expect("load Memory collection");
        let (fragment, id) = memory_model::chunk_fragment(draft).expect("build Memory chunk");
        storage
            .publish_memory(&loaded, fragment)
            .expect("publish Memory chunk");
        id
    }

    #[test]
    fn migrate_legacy_command_is_additive_and_replayable() {
        let pile = TestPile::new();
        let legacy_signer = SigningKey::from_bytes(&[0xA5; 32]);
        let legacy_id = Id::new([0xA6; 16]).unwrap();
        let legacy_store = open_pile_strict(&pile.pile).unwrap();
        let mut repository =
            Repository::new(legacy_store, legacy_signer, Fragment::empty()).unwrap();
        let branch = *repository
            .create_branch(faculties::schemas::memory::LEGACY_MEMORY_BRANCH_NAME, None)
            .unwrap();
        let mut workspace = repository.pull(branch).unwrap();
        let mut legacy = Fragment::empty();
        let summary = legacy.put::<LongString, _>("legacy CLI memory".to_owned());
        legacy += entity! { ExclusiveId::force_ref(&legacy_id) @
            metadata::tag: &faculties::schemas::memory::KIND_CHUNK_ID,
            ctx::summary: summary,
            ctx::start_at: point("2026-02-01T00:00:00"),
            ctx::end_at: point("2026-02-01T01:00:00"),
            metadata::created_at: point("2026-02-01T01:00:00"),
        };
        workspace.commit(legacy, "legacy CLI event");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();

        let storage = pile.storage();
        cmd_migrate_legacy(storage).unwrap();
        let loaded = storage.load().unwrap();
        assert_eq!(loaded.catalog.chunks.len(), 1);
        assert_eq!(loaded.catalog.alias_targets(legacy_id).len(), 1);
        drop(loaded);

        let length = std::fs::metadata(&pile.pile).unwrap().len();
        cmd_migrate_legacy(storage).unwrap();
        assert_eq!(std::fs::metadata(&pile.pile).unwrap().len(), length);
    }

    fn text_draft(summary: &str, start: &str, end: &str) -> memory_model::ChunkDraft {
        memory_model::ChunkDraft {
            content: memory_model::ChunkDraftContent::Text(summary.to_owned()),
            start_at: point(start),
            end_at: point(end),
            lens: None,
            references: BTreeSet::new(),
            about_exec_result: None,
            about_archive_message: None,
            predecessors: BTreeSet::new(),
            observed_at: BTreeSet::from([point(end)]),
            aliases: BTreeSet::new(),
        }
    }

    #[test]
    fn replay_batch_never_splits_one_start_coordinate() {
        let ids: Vec<Id> = (1u8..=5).map(|byte| Id::new([byte; 16]).unwrap()).collect();
        let batch = vec![
            (10, 11, ids[0]),
            (20, 24, ids[1]),
            (20, 23, ids[2]),
            (20, 22, ids[3]),
            (30, 31, ids[4]),
        ];
        assert_eq!(replay_take_count(&batch, 0), 0);
        assert_eq!(replay_take_count(&batch, 1), 1);
        assert_eq!(replay_take_count(&batch, 2), 4);
        assert_eq!(replay_take_count(&batch, 3), 4);
        assert_eq!(replay_take_count(&batch, 5), 5);
        assert_eq!(replay_take_count(&batch, 99), 5);
    }

    #[test]
    fn supersede_joins_unrelated_heads_without_losing_new_state() {
        let pile = TestPile::new();
        let storage = pile.storage();
        let reference = publish_chunk(
            storage,
            text_draft(
                "referenced context",
                "2026-01-01T00:00:00",
                "2026-01-01T01:00:00",
            ),
        );
        let old = publish_chunk(
            storage,
            text_draft(
                "older competing recollection",
                "2026-01-02T00:00:00",
                "2026-01-02T01:00:00",
            ),
        );
        let exec = Id::new([0xE1; 16]).unwrap();
        let archive = Id::new([0xA1; 16]).unwrap();
        let mut rich = text_draft(
            "new state with every optional field",
            "2026-01-03T00:00:00",
            "2026-01-03T01:00:00",
        );
        rich.lens = Some("integration".to_string());
        rich.references.insert(reference);
        rich.about_exec_result = Some(exec);
        rich.about_archive_message = Some(archive);
        let new = publish_chunk(storage, rich);

        cmd_supersede(storage, &[format!("{new:x}"), format!("{old:x}")])
            .expect("join unrelated revisions");
        let after = storage.load().expect("load joined Memory collection");
        let source = &after.catalog.chunks[&new];
        let joined = after
            .catalog
            .chunks
            .values()
            .find(|row| row.predecessors == BTreeSet::from([new, old]))
            .expect("fresh join revision");
        assert_ne!(joined.id, new);
        assert_ne!(joined.id, old);
        assert_eq!(joined.content, source.content);
        assert_eq!(joined.start_at, source.start_at);
        assert_eq!(joined.end_at, source.end_at);
        assert_eq!(joined.lens, source.lens);
        assert_eq!(joined.references, source.references);
        assert_eq!(joined.about_exec_result, source.about_exec_result);
        assert_eq!(joined.about_archive_message, source.about_archive_message);

        let pile_len = std::fs::metadata(&pile.pile).unwrap().len();
        let joined_id = joined.id;
        drop(after);
        cmd_supersede(storage, &[format!("{joined_id:x}"), format!("{old:x}")])
            .expect("already-descended join is idempotent");
        assert_eq!(
            std::fs::metadata(&pile.pile).unwrap().len(),
            pile_len,
            "no-op supersede must not publish another root"
        );
        let error = cmd_supersede(storage, &[format!("{old:x}"), format!("{joined_id:x}")])
            .expect_err("a descendant cannot be named beside its own ancestor");
        assert!(error.to_string().contains("backwards reconciliation"));
        assert_eq!(std::fs::metadata(&pile.pile).unwrap().len(), pile_len);
    }

    #[test]
    fn respan_preserves_content_lens_references_and_provenance() {
        let pile = TestPile::new();
        let storage = pile.storage();
        let reference = publish_chunk(
            storage,
            text_draft("reference", "2026-02-01T00:00:00", "2026-02-01T01:00:00"),
        );
        let mut rich = text_draft(
            "state whose span needs correction",
            "2026-02-02T00:00:00",
            "2026-02-02T01:00:00",
        );
        rich.lens = Some("correction".to_string());
        rich.references.insert(reference);
        rich.about_exec_result = Some(Id::new([0xE2; 16]).unwrap());
        rich.about_archive_message = Some(Id::new([0xA2; 16]).unwrap());
        let old = publish_chunk(storage, rich);

        cmd_respan(
            storage,
            &[
                format!("{old:x}"),
                "2026-02-03T00:00:00..2026-02-03T02:00:00".to_string(),
            ],
        )
        .expect("respan rich revision");
        let after = storage.load().unwrap();
        let source = &after.catalog.chunks[&old];
        let corrected = after
            .catalog
            .chunks
            .values()
            .find(|row| row.predecessors == BTreeSet::from([old]))
            .expect("corrected revision");
        assert_eq!(corrected.content, source.content);
        assert_eq!(corrected.lens, source.lens);
        assert_eq!(corrected.references, source.references);
        assert_eq!(corrected.about_exec_result, source.about_exec_result);
        assert_eq!(
            corrected.about_archive_message,
            source.about_archive_message
        );
        assert_eq!(corrected.start_at, point("2026-02-03T00:00:00"));
        assert_eq!(corrected.end_at, point("2026-02-03T02:00:00"));
    }

    #[test]
    fn historical_aliases_resolve_to_their_exact_intrinsic_revision() {
        let pile = TestPile::new();
        let storage = pile.storage();
        let alias = Id::new([0x71; 16]).unwrap();
        let mut draft = text_draft(
            "migrated revision",
            "2026-03-01T00:00:00",
            "2026-03-01T01:00:00",
        );
        draft.aliases.insert(alias);
        let intrinsic = publish_chunk(storage, draft);
        let loaded = storage.load().unwrap();
        assert_eq!(
            resolve_chunk_id(&loaded, &format!("{alias:x}")).unwrap(),
            intrinsic
        );
        assert_eq!(
            resolve_chunk_id(&loaded, &format!("{alias:x}")[..12]).unwrap(),
            intrinsic
        );
    }

    #[test]
    fn lexical_search_is_rebuilt_from_the_frozen_memory_view() {
        let pile = TestPile::new();
        let storage = pile.storage();
        let matching = publish_chunk(
            storage,
            text_draft(
                "cobalt narwhal migration",
                "2026-04-01T00:00:00",
                "2026-04-01T01:00:00",
            ),
        );
        let unrelated = publish_chunk(
            storage,
            text_draft(
                "violet orchard",
                "2026-04-02T00:00:00",
                "2026-04-02T01:00:00",
            ),
        );
        let loaded = storage.load().unwrap();
        let scores = faculties::memory_cover::lexical_relevance_scores(
            &loaded.memory.facts,
            &loaded.memory.reader,
            "cobalt narwhal",
        )
        .unwrap();
        assert!(scores.get(&matching).copied().unwrap_or_default() > 0.0);
        assert_eq!(scores.get(&unrelated), None);
    }

    /// A fresh cover-state dir under the system temp dir, removed on drop —
    /// the tests never touch the real `~/.cache/faculties/cover/`.
    struct TestStateDir(PathBuf);

    impl TestStateDir {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!("faculties-memory-cover-state-{}", ufoid().id)))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestStateDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Walk `cover continue` steps until the final chunk, returning the
    /// emitted chunk texts in order.
    fn walk_chunks(dir: &Path) -> Vec<String> {
        let mut out = Vec::new();
        loop {
            match cover_advance(dir).expect("advance cover") {
                CoverStep::Chunk { text, complete, .. } => {
                    out.push(text);
                    if complete {
                        return out;
                    }
                }
                CoverStep::AlreadyComplete { .. } => return out,
            }
        }
    }

    #[test]
    fn cover_chunks_reassemble_byte_for_byte() {
        let state = TestStateDir::new();
        // Multi-byte characters spread across chunk boundaries: 7-char chunks
        // land inside the em-dashes unless slicing is character-aware.
        let cover = "memory context — 3 chunk(s)\n\nalpha — beta\ngamma — delta\n";
        let (chunks, total) =
            cover_write_state(state.path(), cover, 7, "t".to_string()).expect("write cover state");
        assert_eq!(total, cover.chars().count());
        assert_eq!(chunks, cover_chunk_count(total, 7));

        let emitted = walk_chunks(state.path());
        assert_eq!(emitted.len(), chunks);
        assert_eq!(emitted.concat(), cover, "reassembly must be byte-for-byte");
        // Every chunk but the last is exactly chunk_chars characters.
        for text in &emitted[..emitted.len() - 1] {
            assert_eq!(text.chars().count(), 7);
        }
    }

    #[test]
    fn cover_status_flips_and_reset_rearms() {
        let state = TestStateDir::new();
        cover_write_state(state.path(), "0123456789", 4, "t".to_string()).expect("write");

        // Fresh cover: incomplete, nothing loaded (exit code 1 in the CLI).
        let (line, complete) = cover_status_line(state.path()).expect("status");
        assert_eq!(line, "complete=false loaded=0/3 chars=0/10");
        assert!(!complete);

        // First chunk: 1/3, chars 0..4, not yet complete.
        match cover_advance(state.path()).expect("advance") {
            CoverStep::Chunk {
                index,
                chunks,
                start_char,
                end_char,
                text,
                complete,
            } => {
                assert_eq!((index, chunks, start_char, end_char), (1, 3, 0, 4));
                assert_eq!(text, "0123");
                assert!(!complete);
            }
            CoverStep::AlreadyComplete { .. } => panic!("expected a chunk"),
        }
        let (line, complete) = cover_status_line(state.path()).expect("status");
        assert_eq!(line, "complete=false loaded=1/3 chars=4/10");
        assert!(!complete);

        // Drain the rest: status flips to complete (exit code 0 in the CLI).
        walk_chunks(state.path());
        let (line, complete) = cover_status_line(state.path()).expect("status");
        assert_eq!(line, "complete=true loaded=3/3 chars=10/10");
        assert!(complete);

        // A further continue is the idempotent nothing-to-do marker.
        match cover_advance(state.path()).expect("advance") {
            CoverStep::AlreadyComplete { chunks } => assert_eq!(chunks, 3),
            CoverStep::Chunk { .. } => panic!("expected AlreadyComplete"),
        }

        // Reset re-arms the cursor without touching the stored cover.
        let pending = cover_reset_cursor(state.path()).expect("reset");
        assert_eq!(pending, 3);
        let (line, complete) = cover_status_line(state.path()).expect("status");
        assert_eq!(line, "complete=false loaded=0/3 chars=0/10");
        assert!(!complete);
        assert_eq!(walk_chunks(state.path()).concat(), "0123456789");
    }

    #[test]
    fn cover_missing_state_semantics() {
        let state = TestStateDir::new();
        // Status on a never-started session reads incomplete (hook blocks)…
        let (line, complete) = cover_status_line(state.path()).expect("status");
        assert_eq!(line, "complete=false loaded=0/0 chars=0/0");
        assert!(!complete);
        // …while continue and reset refuse outright: there is nothing to read.
        assert!(cover_advance(state.path()).is_err());
        assert!(cover_reset_cursor(state.path()).is_err());
    }

    #[test]
    fn cover_start_generates_the_context_cover_from_a_pile() {
        let pile = TestPile::new();
        let storage = pile.storage();
        // Seed a coarse apex over two fine day-chunks — the shape the
        // antichain cover splits when the budget allows.
        let apex = (
            parse_tai_timestamp("2026-01-01T00:00:00").unwrap(),
            parse_tai_timestamp("2026-01-03T00:00:00").unwrap(),
        );
        let loaded = storage.load().expect("load empty collections");
        create_chunk(
            storage,
            &loaded,
            "apex: two days of cover-cursor work",
            apex,
            None,
            apex.1,
        )
        .expect("create apex");
        let day1 = (
            parse_tai_timestamp("2026-01-01T00:00:00").unwrap(),
            parse_tai_timestamp("2026-01-02T00:00:00").unwrap(),
        );
        let loaded = storage.load().expect("reload after apex");
        create_chunk(
            storage,
            &loaded,
            "day one: built the state machine",
            day1,
            None,
            day1.1,
        )
        .expect("create day one");
        let day2 = (
            parse_tai_timestamp("2026-01-02T00:00:00").unwrap(),
            parse_tai_timestamp("2026-01-03T00:00:00").unwrap(),
        );
        let loaded = storage.load().expect("reload after day one");
        create_chunk(
            storage,
            &loaded,
            "day two: wired the hooks",
            day2,
            None,
            day2.1,
        )
        .expect("create day two");

        // The exact text `memory context --chars 10000` would print.
        let loaded = storage
            .load_context(false)
            .expect("load seeded collections");
        let cover = build_context_cover(&loaded, 10_000, None, None, None, DEFAULT_SIM_THRESHOLD)
            .expect("build context cover");
        // The status header now goes to stderr, not into the returned/ingested
        // cover text (prefix-stability + ranges-are-the-drill-key de-noise).
        assert!(!cover.contains("memory context — "));
        assert!(cover.contains("day one: built the state machine"));
        assert!(cover.contains("day two: wired the hooks"));

        // Store + walk exactly as `cover start` / `cover continue` do.
        let state = TestStateDir::new();
        let (chunks, total) =
            cover_write_state(state.path(), &cover, 50, "t".to_string()).expect("write");
        assert_eq!(total, cover.chars().count());
        let emitted = walk_chunks(state.path());
        assert_eq!(emitted.len(), chunks);
        assert_eq!(
            emitted.concat(),
            cover,
            "chunk reassembly must equal the stored cover"
        );
    }
}
