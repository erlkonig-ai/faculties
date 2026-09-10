//! Resident Memory operations over frozen maintained views. No argv, host input
//! expansion, ambient persona, or temporary image files live in this module.
//! The shared memory_cover module remains the sole recollection algorithm.

use crate::memory_cover::CoverReport;
#[cfg(test)]
use crate::memory_cover::DEFAULT_SIM_THRESHOLD;
use crate::out::Out;

#[derive(Clone, Debug)]
pub struct Memory {
    storage: crate::storage::Storage,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CreatedMemory {
    pub id: Id,
    pub start: Epoch,
    pub end: Epoch,
}
impl CreatedMemory {
    pub fn emit(&self, out: &mut Out<'_>) -> Result<()> {
        out.line(format!(
            "range: {}",
            format_time_range(self.start, self.end)
        ))?;
        out.line(format!("id: {:x}", self.id))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RespanReceipt {
    pub memory: CreatedMemory,
    pub previous: Id,
    pub previous_range: String,
}
impl RespanReceipt {
    pub fn emit(&self, out: &mut Out<'_>) -> Result<()> {
        self.memory.emit(out)?;
        out.line(format!(
            "  the same memory as {:x} ({}), which stands aside",
            self.previous, self.previous_range
        ))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ChurnOptions {
    pub budget_chars: usize,
    pub steps: usize,
    pub step_units: i128,
}
impl Default for ChurnOptions {
    fn default() -> Self {
        Self {
            budget_chars: 800_000,
            steps: 160,
            step_units: 1,
        }
    }
}

impl Memory {
    /// Pile/key paths belong to the trusted launcher, never an MCP tool caller.
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self { storage }
    }
    fn storage(&self) -> MemoryStorage<'_> {
        MemoryStorage {
            storage: &self.storage,
        }
    }

    /// An id/alias prefix or a temporal range is a domain selector, not argv.
    pub fn show(&self, selector: &str, out: &mut Out<'_>) -> Result<()> {
        self.show_many(&[selector.to_owned()], out)
    }
    /// All selectors resolve against one frozen Memory view; retain input order.
    pub fn show_many(&self, selectors: &[String], out: &mut Out<'_>) -> Result<()> {
        let loaded = self.storage().load()?;
        for (index, raw) in selectors.iter().enumerate() {
            let id = if raw.contains("..") {
                let (start, end) = parse_time_range(raw)?;
                find_chunk_by_time_range(&loaded.memory.facts, start, end)
                    .ok_or_else(|| anyhow!("no memory covers range {raw}"))?
            } else {
                resolve_chunk_id(&loaded, raw)
                    .map_err(|error| invalid_memory_id_error(raw, error))?
            };
            if index != 0 {
                out.line("")?;
            }
            print_chunk(&loaded.memory.reader, &loaded.memory.facts, id, out)?;
        }
        Ok(())
    }
    pub fn turn(&self, turn: &str, out: &mut Out<'_>) -> Result<()> {
        let loaded = self.storage().load()?;
        print_turn_facets(&loaded.memory.reader, &loaded.memory.facts, turn, out)
    }
    pub fn meta(&self, selector: &str, out: &mut Out<'_>) -> Result<()> {
        meta(self.storage(), selector, out)
    }
    pub fn provenance(&self, id: &str, out: &mut Out<'_>) -> Result<()> {
        provenance(self.storage(), id, out)
    }
    pub fn search(&self, query: &str, out: &mut Out<'_>) -> Result<()> {
        search(self.storage(), query, out)
    }
    pub fn similar(&self, query: &str, out: &mut Out<'_>) -> Result<()> {
        similar(self.storage(), query, out)
    }
    pub fn embed(&self, out: &mut Out<'_>) -> Result<()> {
        embed(self.storage(), out)
    }
    pub fn lens(&self, theme: Option<&str>, out: &mut Out<'_>) -> Result<()> {
        lens(self.storage(), theme, out)
    }
    pub fn list(&self, grain: Option<&str>, out: &mut Out<'_>) -> Result<()> {
        list(self.storage(), grain, out)
    }
    pub fn check(&self, grain: &str, out: &mut Out<'_>) -> Result<()> {
        check(self.storage(), grain, out)
    }
    pub fn density(&self, grain: Option<&str>, out: &mut Out<'_>) -> Result<()> {
        density(self.storage(), grain, out)
    }
    pub fn churn(&self, options: &ChurnOptions, out: &mut Out<'_>) -> Result<()> {
        if options.step_units <= 0 {
            bail!("churn step_units must be positive");
        }
        options
            .step_units
            .checked_mul(crate::memory_cover::REPLAY_QUANTUM_NS)
            .and_then(|step| step.checked_mul(options.steps as i128))
            .filter(|duration| *duration <= i128::MAX / 2)
            .ok_or_else(|| anyhow!("churn diagnostic time span is too large"))?;
        churn(self.storage(), options, out)
    }
    pub fn respan_instants(&self, dry_run: bool, out: &mut Out<'_>) -> Result<()> {
        respan_instants(self.storage(), dry_run, out)
    }
    pub fn respan_seams(&self, dry_run: bool, out: &mut Out<'_>) -> Result<()> {
        respan_seams(self.storage(), dry_run, out)
    }

    /// Summary/lens strings are literal resident data, including @ prefixes.
    pub fn create(
        &self,
        summary: &str,
        range: Option<(Epoch, Epoch)>,
        lens: Option<&str>,
    ) -> Result<CreatedMemory> {
        if summary.is_empty() {
            bail!("memory summary must not be empty");
        }
        let range = match range {
            Some(range) => range,
            None => {
                let now = clock::now()?;
                (now - moment(), now)
            }
        };
        require_duration(range)?;
        let storage = self.storage();
        let loaded = storage.load()?;
        let id = create_chunk(storage, &loaded, summary, range, lens, range.1)?;
        Ok(CreatedMemory {
            id,
            start: range.0,
            end: range.1,
        })
    }
    /// Store exact resident bytes. Presentation validates/derives a view later;
    /// storage does not decode, convert, or relabel the image.
    pub fn image(&self, bytes: &[u8], range: (Epoch, Epoch)) -> Result<CreatedMemory> {
        let id = create_image_chunk(self.storage(), bytes, range)?;
        Ok(CreatedMemory {
            id,
            start: range.0,
            end: range.1,
        })
    }
    pub fn respan(&self, previous: &str, range: (Epoch, Epoch)) -> Result<RespanReceipt> {
        require_duration(range)?;
        let storage = self.storage();
        let loaded = storage.load()?;
        let previous = resolve_chunk_id(&loaded, previous)?;
        let (fragment, id) = respan_fragment(&loaded, previous, range, clock::now()?)?;
        storage.publish_memory(fragment)?;
        Ok(RespanReceipt {
            memory: CreatedMemory {
                id,
                start: range.0,
                end: range.1,
            },
            previous,
            previous_range: chunk_span_str(&loaded.memory.facts, previous),
        })
    }
    /// Exact charged text is separate from diagnostics, including fail-open
    /// filter/remove warnings. Selection and emitted SPACE order are unchanged.
    pub fn context(&self, options: &CoverOpts) -> Result<CoverReport> {
        if !options.sim_threshold.is_finite() || !(0.0..=1.0).contains(&options.sim_threshold) {
            bail!("sim_threshold must be a finite number in [0, 1]");
        }
        let needs_embeddings = cfg!(feature = "local-embed")
            && (options.about.is_some() || options.filter.is_some() || options.remove.is_some());
        let loaded = self.storage().load_context(needs_embeddings)?;
        render_context(&loaded, options)
    }
    pub fn consolidate_start(&self, persona: &str, edge: Epoch) -> Result<()> {
        self.set_cursor(CONSOLIDATE_STREAM, persona, Some(edge), None)
    }
    pub fn consolidate_stop(&self, persona: &str) -> Result<()> {
        self.set_cursor(CONSOLIDATE_STREAM, persona, None, None)
    }
    pub fn replay_start(&self, persona: &str, grain: &str, from: Option<Epoch>) -> Result<()> {
        parse_grain(grain)?;
        let from = from.unwrap_or_else(|| Epoch::from_gregorian_tai(1970, 1, 1, 0, 0, 0, 0));
        self.set_cursor(
            MEMORY_REPLAY_STREAM,
            persona,
            Some(from - Duration::from_total_nanoseconds(1)),
            Some(grain),
        )
    }
    pub fn replay_stop(&self, persona: &str) -> Result<()> {
        self.set_cursor(MEMORY_REPLAY_STREAM, persona, None, None)
    }
    fn set_cursor(
        &self,
        stream: &str,
        persona: &str,
        position: Option<Epoch>,
        grain: Option<&str>,
    ) -> Result<()> {
        require_persona(persona)?;
        let storage = self.storage();
        let loaded = storage.load_comb()?;
        comb_advance(storage, &loaded, stream, persona, position, grain)
    }
}

fn require_persona(persona: &str) -> Result<()> {
    if persona.is_empty() {
        bail!("persona must be explicit and nonempty");
    }
    Ok(())
}

fn render_context(loaded: &LoadedContext, options: &CoverOpts) -> Result<CoverReport> {
    if let Some(embeddings) = loaded.embeddings.as_ref() {
        crate::memory_cover::render_cover_report(
            &loaded.memory.memory.facts,
            &embeddings.facts,
            &loaded.memory.memory.reader,
            options,
        )
    } else {
        crate::memory_cover::render_cover_report(
            &loaded.memory.memory.facts,
            &TribleSet::new(),
            &loaded.memory.memory.reader,
            options,
        )
    }
}

/// Legacy fixture seam; the report and text-only API must agree byte-for-byte.
#[cfg(test)]
fn build_context_cover(
    loaded: &LoadedContext,
    budget_chars: usize,
    chunk_overhead: usize,
    about: Option<&str>,
    filter_q: Option<&str>,
    remove_q: Option<&str>,
    sim_threshold: f32,
) -> Result<String> {
    let options = CoverOpts {
        budget_chars,
        chunk_overhead,
        about: about.map(str::to_owned),
        filter: filter_q.map(str::to_owned),
        remove: remove_q.map(str::to_owned),
        sim_threshold,
    };
    Ok(render_context(loaded, &options)?.text)
}

fn emit_image(
    reader: &PileSnapshot,
    handle: Inline<Handle<RawBytes>>,
    out: &mut Out<'_>,
) -> Result<()> {
    let bytes: Bytes = reader.get(handle).context("read image bytes")?;
    let format =
        image::guess_format(bytes.as_ref()).context("memory image has no recognized format")?;
    let part = crate::files::presentation::present(
        bytes,
        format.to_mime_type(),
        &crate::files::presentation::ViewOptions::default(),
    )
    .context("present memory image (stored bytes remain unchanged)")?;
    out.emit(part)
}

use std::collections::BTreeSet;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

use crate::schemas::embeddings::DEFAULT_SCOPE_ID as EMBEDDINGS_SCOPE_ID;
#[cfg(feature = "local-embed")]
use crate::schemas::embeddings::{self, Embedding768};
use crate::schemas::memory::{
    archive_schema as legacy_archive_schema, ctx, DEFAULT_COMB_SCOPE_ID,
    DEFAULT_SCOPE_ID as MEMORY_SCOPE_ID,
};
use crate::schemas::{blockdag as archive_schema, cognition as cognition_schema};
use crate::storage::FactArchive;
use anyhow::{anyhow, bail, Context, Result};
// The shared recollection renderer and accessors also serve Orient in-process.
use crate::collection_names::open_configured;
use crate::memory_cover::{
    all_chunk_ids, chunk_about_archive_message, chunk_about_exec_result, chunk_aliases,
    chunk_end_at, chunk_image_handle, chunk_lens_handle, chunk_observed_at, chunk_references,
    chunk_span_str, chunk_start_at, chunk_summary_handle, collect_chunk_spans,
    epoch_end_from_interval, epoch_from_interval, fmt_epoch, format_time_range, interval_key,
    key_to_epoch, CoverOpts,
};
#[cfg(feature = "local-embed")]
use crate::memory_cover::{chunk_embedding_handle, l2_normalize};
use crate::{clock, cognition as cognition_model, comb as comb_model, memory as memory_model};
use hifitime::{Duration, Epoch};
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::blob::Bytes;
use triblespace::core::collection::{CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::BlobStoreGet;
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval};
use triblespace::prelude::*;

#[derive(Clone, Copy)]
struct MemoryStorage<'a> {
    storage: &'a crate::storage::Storage,
}

struct CollectionView {
    facts: FactArchive,
    reader: PileSnapshot,
}

struct LoadedMemory {
    memory: CollectionView,
}

struct LoadedContext {
    memory: LoadedMemory,
    embeddings: Option<CollectionView>,
}

struct LoadedComb {
    memory: LoadedMemory,
    comb: CollectionView,
}

struct LoadedProvenance {
    memory: LoadedMemory,
    cognition: CollectionView,
    archive: CollectionView,
}

impl MemoryStorage<'_> {
    fn attach_collection(
        collection: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
        store_snapshot: &PileSnapshot,
        label: &str,
    ) -> Result<CollectionView> {
        let facts = store_snapshot
            .collection(collection)
            .with_context(|| format!("observe maintained {label} collection"))?
            .view::<FactArchive>()
            .with_context(|| format!("attach maintained {label} collection"))?;
        Ok(CollectionView {
            facts,
            reader: store_snapshot.clone(),
        })
    }

    fn load_memory_from_snapshot(
        collection: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
        store_snapshot: &PileSnapshot,
    ) -> Result<LoadedMemory> {
        let memory = Self::attach_collection(collection, store_snapshot, "Memory")?;
        Ok(LoadedMemory { memory })
    }

    /// Freeze maintained Memory alone for ordinary commands.
    fn load(&self) -> Result<LoadedMemory> {
        self.storage.with_pile(|pile, signer| {
            let result = pollster::block_on(async {
                let source = open_configured(pile, MEMORY_SCOPE_ID, signer.verifying_key())?;
                let policy = source
                    .policy(
                        &pile
                            .snapshot()
                            .context("freeze Memory descriptor snapshot")?,
                    )
                    .context("read Memory collection policy")?;
                let succinct = pile
                    .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
                    .context("register Succinct Memory collection")?;
                let collection = pile
                    .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
                    .context("register Rank9 Memory collection")?;
                drop(pile.ensure(source).await.context("ensure Memory source")?);
                drop(
                    pile.maintain(succinct)
                        .await
                        .context("maintain Succinct Memory collection")?,
                );
                let store_snapshot = pile
                    .maintain(collection)
                    .await
                    .context("maintain Rank9 Memory collection")?;
                Self::load_memory_from_snapshot(collection, &store_snapshot)
            });
            result
        })
    }

    /// Freeze Memory and shared Embeddings from one snapshot for semantic or
    /// context-cover reads.
    fn load_context(&self, with_embeddings: bool) -> Result<LoadedContext> {
        self.storage.with_pile(|pile, signer| {
            let result = pollster::block_on(async {
                let memory_source = open_configured(pile, MEMORY_SCOPE_ID, signer.verifying_key())?;
                let memory_policy = memory_source
                    .policy(
                        &pile
                            .snapshot()
                            .context("freeze Memory descriptor snapshot")?,
                    )
                    .context("read Memory collection policy")?;
                let memory_succinct = pile
                    .derive::<SuccinctArchiveBlob>(memory_source, (), memory_policy.clone())
                    .context("register Succinct Memory collection")?;
                let memory_collection = pile
                    .derive::<Rank9AcceleratedSuccinctArchiveBlob>(
                        memory_succinct,
                        (),
                        memory_policy,
                    )
                    .context("register Rank9 Memory collection")?;
                let embeddings_collections = if with_embeddings {
                    let source =
                        open_configured(pile, EMBEDDINGS_SCOPE_ID, signer.verifying_key())?;
                    let policy = source
                        .policy(
                            &pile
                                .snapshot()
                                .context("freeze shared Embeddings descriptor snapshot")?,
                        )
                        .context("read shared Embeddings collection policy")?;
                    let succinct = pile
                        .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
                        .context("register Succinct shared Embeddings collection")?;
                    let rank9 = pile
                        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
                        .context("register Rank9 shared Embeddings collection")?;
                    Some((source, succinct, rank9))
                } else {
                    None
                };
                drop(pile.ensure(memory_source).await?);
                if let Some((source, _, _)) = embeddings_collections {
                    drop(pile.ensure(source).await?);
                }
                drop(
                    pile.maintain(memory_succinct)
                        .await
                        .context("maintain Succinct Memory collection")?,
                );
                drop(
                    pile.maintain(memory_collection)
                        .await
                        .context("maintain Rank9 Memory collection")?,
                );
                if let Some((_, succinct, rank9)) = embeddings_collections {
                    drop(
                        pile.maintain(succinct)
                            .await
                            .context("maintain Succinct shared Embeddings collection")?,
                    );
                    drop(
                        pile.maintain(rank9)
                            .await
                            .context("maintain Rank9 shared Embeddings collection")?,
                    );
                }
                let store_snapshot = pile
                    .snapshot()
                    .context("freeze maintained Memory/Embeddings snapshot")?;
                let memory = Self::load_memory_from_snapshot(memory_collection, &store_snapshot)?;
                let embeddings = match embeddings_collections {
                    Some((_, _, collection)) => Some(Self::attach_collection(
                        collection,
                        &store_snapshot,
                        "shared Embeddings",
                    )?),
                    None => None,
                };
                Ok(LoadedContext { memory, embeddings })
            });
            result
        })
    }

    /// Freeze Memory and Comb together for cursor transitions.
    fn load_comb(&self) -> Result<LoadedComb> {
        self.storage.with_pile(|pile, signer| {
            let result = pollster::block_on(async {
                let memory_source = open_configured(pile, MEMORY_SCOPE_ID, signer.verifying_key())?;
                let memory_policy = memory_source
                    .policy(
                        &pile
                            .snapshot()
                            .context("freeze Memory descriptor snapshot")?,
                    )
                    .context("read Memory collection policy")?;
                let memory_succinct = pile
                    .derive::<SuccinctArchiveBlob>(memory_source, (), memory_policy.clone())
                    .context("register Succinct Memory collection")?;
                let memory_collection = pile
                    .derive::<Rank9AcceleratedSuccinctArchiveBlob>(
                        memory_succinct,
                        (),
                        memory_policy,
                    )
                    .context("register Rank9 Memory collection")?;
                let comb_source =
                    open_configured(pile, DEFAULT_COMB_SCOPE_ID, signer.verifying_key())?;
                let comb_policy = comb_source
                    .policy(&pile.snapshot().context("freeze Comb descriptor snapshot")?)
                    .context("read Comb collection policy")?;
                let comb_succinct = pile
                    .derive::<SuccinctArchiveBlob>(comb_source, (), comb_policy.clone())
                    .context("register Succinct Comb collection")?;
                let comb_collection = pile
                    .derive::<Rank9AcceleratedSuccinctArchiveBlob>(comb_succinct, (), comb_policy)
                    .context("register Rank9 Comb collection")?;
                drop(pile.ensure(memory_source).await?);
                drop(pile.ensure(comb_source).await?);
                drop(
                    pile.maintain(memory_succinct)
                        .await
                        .context("maintain Succinct Memory collection")?,
                );
                drop(
                    pile.maintain(memory_collection)
                        .await
                        .context("maintain Rank9 Memory collection")?,
                );
                drop(
                    pile.maintain(comb_succinct)
                        .await
                        .context("maintain Succinct Comb collection")?,
                );
                drop(
                    pile.maintain(comb_collection)
                        .await
                        .context("maintain Rank9 Comb collection")?,
                );
                let store_snapshot = pile
                    .snapshot()
                    .context("freeze maintained Memory/Comb snapshot")?;
                let memory = Self::load_memory_from_snapshot(memory_collection, &store_snapshot)?;
                let comb = Self::attach_collection(comb_collection, &store_snapshot, "Comb")?;
                Ok(LoadedComb { memory, comb })
            });
            result
        })
    }

    /// Freeze Memory, Cognition, and Archive from exactly one pile snapshot
    /// for a coherent cross-scope provenance read.
    fn load_provenance(&self) -> Result<LoadedProvenance> {
        self.storage.with_pile(|pile, signer| {
            let result = pollster::block_on(async {
                let memory_source = open_configured(pile, MEMORY_SCOPE_ID, signer.verifying_key())?;
                let cognition_source = open_configured(
                    pile,
                    cognition_schema::DEFAULT_SCOPE_ID,
                    signer.verifying_key(),
                )?;
                let archive_source = open_configured(
                    pile,
                    archive_schema::DEFAULT_SCOPE_ID,
                    signer.verifying_key(),
                )?;
                let memory_policy = memory_source
                    .policy(
                        &pile
                            .snapshot()
                            .context("freeze Memory descriptor snapshot")?,
                    )
                    .context("read Memory collection policy")?;
                let memory_succinct = pile
                    .derive::<SuccinctArchiveBlob>(memory_source, (), memory_policy.clone())
                    .context("register Succinct Memory collection")?;
                let memory_collection = pile
                    .derive::<Rank9AcceleratedSuccinctArchiveBlob>(
                        memory_succinct,
                        (),
                        memory_policy,
                    )
                    .context("register Rank9 Memory collection")?;
                let cognition_policy = cognition_source
                    .policy(
                        &pile
                            .snapshot()
                            .context("freeze Cognition descriptor snapshot")?,
                    )
                    .context("read Cognition collection policy")?;
                let cognition_succinct = pile
                    .derive::<SuccinctArchiveBlob>(cognition_source, (), cognition_policy.clone())
                    .context("register Succinct Cognition collection")?;
                let cognition_collection = pile
                    .derive::<Rank9AcceleratedSuccinctArchiveBlob>(
                        cognition_succinct,
                        (),
                        cognition_policy,
                    )
                    .context("register Rank9 Cognition collection")?;
                let archive_policy = archive_source
                    .policy(
                        &pile
                            .snapshot()
                            .context("freeze Archive descriptor snapshot")?,
                    )
                    .context("read Archive collection policy")?;
                let archive_succinct = pile
                    .derive::<SuccinctArchiveBlob>(archive_source, (), archive_policy.clone())
                    .context("register Succinct Archive collection")?;
                let archive_collection = pile
                    .derive::<Rank9AcceleratedSuccinctArchiveBlob>(
                        archive_succinct,
                        (),
                        archive_policy,
                    )
                    .context("register Rank9 Archive collection")?;
                for source in [memory_source, cognition_source, archive_source] {
                    drop(pile.ensure(source).await?);
                }
                for (succinct, collection, label) in [
                    (memory_succinct, memory_collection, "Memory"),
                    (cognition_succinct, cognition_collection, "Cognition"),
                    (archive_succinct, archive_collection, "Archive"),
                ] {
                    drop(
                        pile.maintain(succinct)
                            .await
                            .with_context(|| format!("maintain Succinct {label} collection"))?,
                    );
                    drop(
                        pile.maintain(collection)
                            .await
                            .with_context(|| format!("maintain Rank9 {label} collection"))?,
                    );
                }
                let store_snapshot = pile
                    .snapshot()
                    .context("freeze maintained Memory/Cognition/Archive snapshot")?;
                let memory = Self::load_memory_from_snapshot(memory_collection, &store_snapshot)?;
                Ok(LoadedProvenance {
                    memory,
                    cognition: Self::attach_collection(
                        cognition_collection,
                        &store_snapshot,
                        "Cognition",
                    )?,
                    archive: Self::attach_collection(
                        archive_collection,
                        &store_snapshot,
                        "Archive",
                    )?,
                })
            });
            result
        })
    }

    fn publish_memory(&self, fragment: Fragment) -> Result<()> {
        self.storage.with_pile(|pile, signer| {
            let collection = open_configured(pile, MEMORY_SCOPE_ID, signer.verifying_key())?;
            let result = pile
                .commit(collection, signer, fragment)
                .context("commit authored Memory fragment")
                .map(|_| ());
            result
        })
    }

    #[cfg(feature = "local-embed")]
    fn publish_embeddings(&self, fragment: Fragment) -> Result<()> {
        self.storage.with_pile(|pile, signer| {
            let collection = open_configured(pile, EMBEDDINGS_SCOPE_ID, signer.verifying_key())?;
            let result = pile
                .commit(collection, signer, fragment)
                .context("commit authored embedding observations")
                .map(|_| ());
            result
        })
    }

    fn publish_comb(&self, fragment: Fragment) -> Result<()> {
        self.storage.with_pile(|pile, signer| {
            let collection = open_configured(pile, DEFAULT_COMB_SCOPE_ID, signer.verifying_key())?;
            let result = pile
                .commit(collection, signer, fragment)
                .context("commit authored Comb cursor")
                .map(|_| ());
            result
        })
    }
}

// ── on-demand chunk queries ───────────────────────────────────────────
// Chunks are queried directly from their maintained pattern — no flattening.

/// One-line render of a chunk for list/similar output: the summary's first
/// line, or a wordless-image marker, or empty.
fn chunk_oneline<P: TriblePattern>(reader: &PileSnapshot, space: &P, id: Id) -> String {
    if let Some(h) = chunk_summary_handle(space, id) {
        return reader
            .get::<View<str>, UTF8String>(h)
            .ok()
            .map(|v| v.as_ref().lines().next().unwrap_or("").to_string())
            .unwrap_or_default();
    }
    if chunk_image_handle(space, id).is_some() {
        return format!("[image memory @ {}]", chunk_span_str(space, id));
    }
    String::new()
}

// ---------------------------------------------------------------------------
// time-range helpers
// ---------------------------------------------------------------------------

pub fn parse_tai_timestamp(s: &str) -> Result<Epoch> {
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
    Epoch::maybe_from_gregorian_tai(y, m, d, hh, mm, ss, 0)
        .map_err(|error| anyhow!("invalid timestamp {s}: {error}"))
}

pub fn parse_time_range(s: &str) -> Result<(Epoch, Epoch)> {
    let Some((from_str, to_str)) = s.split_once("..") else {
        bail!("invalid time range (expected `from..to`): {s}");
    };
    // Bare TAI is the written form; a trailing Z, a +HH:MM offset, a space for
    // the T, or a missing seconds field are accepted and normalised, so a range
    // can never fold into the summary because of one letter (three junk
    // memories, 2026-09-05).
    let from = parse_tai_timestamp(from_str)
        .or_else(|_| {
            parse_written_stamp(from_str).ok_or_else(|| anyhow!("invalid timestamp: {from_str}"))
        })
        .context("parsing range start")?;
    let to = parse_tai_timestamp(to_str)
        .or_else(|_| {
            parse_written_stamp(to_str).ok_or_else(|| anyhow!("invalid timestamp: {to_str}"))
        })
        .context("parsing range end")?;
    if to < from {
        bail!("a time range runs forward, and this one ends before it starts: {s}");
    }
    Ok((from, to))
}

/// A memory lasts. An explicit range that is an instant is refused with the
/// remedy; a rangeless create spans the moment ending now (see
/// [`memory_model::MOMENT_SECONDS`]).
fn require_duration(range: (Epoch, Epoch)) -> Result<()> {
    if range.1 <= range.0 {
        bail!(
            "a memory lasts: {} is an instant. Give the span it covers (from..to), or leave the \
             range out to mean the moment ending now ({}s).",
            format_time_range(range.0, range.1),
            memory_model::MOMENT_SECONDS
        );
    }
    Ok(())
}

fn moment() -> Duration {
    Duration::from_seconds(memory_model::MOMENT_SECONDS)
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
fn find_chunk_by_time_range<P: TriblePattern>(
    space: &P,
    query_start: Epoch,
    query_end: Epoch,
) -> Option<Id> {
    let query_start_ns = query_start.to_tai_duration().total_nanoseconds();
    let query_end_ns = query_end.to_tai_duration().total_nanoseconds();

    let mut best: Option<(Id, i128)> = None; // (id, specificity score)

    for (chunk_start, chunk_end, chunk_id) in collect_chunk_spans(space) {
        if chunk_start > query_end_ns || chunk_end < query_start_ns {
            continue;
        }

        let overlap_start = chunk_start.max(query_start_ns);
        let overlap_end = chunk_end.min(query_end_ns);
        let overlap = overlap_end.saturating_sub(overlap_start);
        let width = chunk_end - chunk_start;
        let score = 2 * overlap - width;
        match best {
            Some((prev_id, prev_score))
                if prev_score > score || (prev_score == score && prev_id <= chunk_id) => {}
            _ => best = Some((chunk_id, score)),
        }
    }

    best.map(|(id, _)| id)
}

// ── exact BM25 search over the frozen Memory collection ───────────────

fn search(storage: MemoryStorage<'_>, query: &str, out: &mut Out<'_>) -> Result<()> {
    if query.is_empty() {
        bail!("memory search requires a query");
    }
    let loaded = storage.load()?;
    let mut rows: Vec<(Id, f32)> = crate::memory_cover::lexical_relevance_scores(
        &loaded.memory.facts,
        &loaded.memory.reader,
        &query,
    )?
    .into_iter()
    .collect();
    rows.sort_unstable_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    if rows.is_empty() {
        out.line(format!("no matches."))?;
        return Ok(());
    }
    for (chunk, score) in rows.into_iter().take(10) {
        let summary = chunk_oneline(&loaded.memory.reader, &loaded.memory.facts, chunk);
        out.line(format!("{score:6.2}  {chunk:x}  {summary}"))?;
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
// `crate::nomic` seam. Import and legacy migration belong in Mary, outside
// ordinary memory operation.

#[cfg(feature = "local-embed")]
use crate::nomic;

/// `memory embed` — embed every journal chunk that lacks a vector and
/// store it as an observation in the shared Embeddings collection. Idempotent:
/// re-running only embeds chunks absent from the frozen observation set.
#[cfg(feature = "local-embed")]
fn embed(storage: MemoryStorage<'_>, out: &mut Out<'_>) -> Result<()> {
    use mary::embed::LocalEmbedder;

    // What a chunk embeds FROM: its summary prose (nomic-text) or its raw image
    // bytes (nomic-vision). Both land on the same `embeddings::attr::embedding`
    // because nomic text+vision share one 768-d space.
    enum Src {
        Text(Inline<Handle<UTF8String>>),
        Image(Inline<Handle<RawBytes>>),
    }

    let loaded = storage.load_context(true)?;
    let space = &loaded.memory.memory.facts;
    let mut todo: Vec<(Id, Src)> = Vec::new();
    for chunk in all_chunk_ids(space) {
        if chunk_embedding_handle(
            &loaded
                .embeddings
                .as_ref()
                .expect("load_context(true) attaches Embeddings")
                .facts,
            chunk,
        )?
        .is_some()
        {
            continue;
        }
        // An image chunk is wordless — route it to vision; otherwise embed
        // its summary with text. Local writers emit one content value; an
        // additive imported row with several remains readable through the
        // deterministic typed accessors above.
        if let Some(h) = chunk_image_handle(space, chunk) {
            todo.push((chunk, Src::Image(h)));
        } else if let Some(h) = chunk_summary_handle(space, chunk) {
            todo.push((chunk, Src::Text(h)));
        }
    }
    if todo.is_empty() {
        out.line(format!("all journal chunks already embedded."))?;
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
                        out.line(format!("memory: loading nomic-embed-text (once)…"))?;
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
                        out.line(format!("memory: loading nomic-embed-vision (once)…"))?;
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
            out.line(format!("  embedded {}/{total}", i + 1))?;
        }
    }
    storage.publish_embeddings(fragment)?;
    out.line(format!(
        "embedded {n_text} text + {n_image} image chunk(s) into the shared nomic space."
    ))?;
    Ok(())
}

#[cfg(not(feature = "local-embed"))]
fn embed(_storage: MemoryStorage<'_>, _out: &mut Out<'_>) -> Result<()> {
    bail!("`memory embed` needs the local embedder — rebuild with `--features local-embed`");
}

/// `memory similar <query>` — nearest chunks to a free-text query in the shared
/// nomic space. Matches by meaning, not tokens (the semantic complement to
/// `memory search`). Reads stored vectors only; `memory embed` builds them.
#[cfg(feature = "local-embed")]
fn similar(storage: MemoryStorage<'_>, query: &str, out: &mut Out<'_>) -> Result<()> {
    if query.is_empty() {
        bail!("memory similar requires a query");
    }
    out.line(format!("memory: loading nomic-embed-text (once)…"))?;
    let emb = nomic::load_text_embedder()?;
    let qv = l2_normalize(
        emb.embed_query(&query)
            .map_err(|e| anyhow!("embed query: {e:?}"))?,
    );

    let loaded = storage.load_context(true)?;
    let space = &loaded.memory.memory.facts;
    let mut pairs: Vec<(Id, Vec<f32>)> = Vec::new();
    for chunk in all_chunk_ids(space) {
        let embeddings = loaded
            .embeddings
            .as_ref()
            .expect("load_context(true) attaches Embeddings");
        if let Some(h) = chunk_embedding_handle(&embeddings.facts, chunk)? {
            let v: View<[f32]> = embeddings
                .reader
                .get(h)
                .map_err(|e| anyhow!("read embedding: {e:?}"))?;
            pairs.push((chunk, v.as_ref().to_vec()));
        }
    }
    if pairs.is_empty() {
        bail!("no chunk embeddings on this pile yet — run `memory embed` first");
    }
    let total = all_chunk_ids(space).len();
    if pairs.len() < total {
        out.line(format!(
            "note: {} journal chunk(s) not yet embedded — run `memory embed` to refresh",
            total - pairs.len()
        ))?;
    }
    let ranked = embeddings::nearest(&pairs, &qv, 0.0).map_err(|e| anyhow!("nearest: {e:?}"))?;
    if ranked.is_empty() {
        out.line(format!("no matches."))?;
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
        out.line(format!("{cos:6.3}  {chunk:x}  {span}\n        {summary}"))?;
        if let Some(handle) = chunk_image_handle(space, chunk) {
            emit_image(&loaded.memory.memory.reader, handle, out)?;
        }
    }
    Ok(())
}

#[cfg(not(feature = "local-embed"))]
fn similar(_storage: MemoryStorage<'_>, _query: &str, _out: &mut Out<'_>) -> Result<()> {
    bail!("`memory similar` needs the local embedder — rebuild with `--features local-embed`");
}

// ---------------------------------------------------------------------------
// create subcommand
// ---------------------------------------------------------------------------

/// `memory respan <id> <from>..<to>` -- the same memory over corrected time
/// coordinates. A new chunk with the identical text, lens, references and
/// provenance is written over the new range and supersedes the old one; the
/// cover then shows the new coordinates and the old chunk stands aside, still
/// a member of the journal and readable by id. The text cannot change here:
/// that would be a new memory, and a journal is not a mutable fact store.

/// The respan itself: the old chunk's text, lens, references and provenance
/// over `range`, plus the edge. Shared by `respan` and `respan-instants`.
fn respan_fragment(
    loaded: &LoadedMemory,
    old: Id,
    range: (Epoch, Epoch),
    now: Epoch,
) -> Result<(Fragment, Id)> {
    let space = &loaded.memory.facts;
    let reader = &loaded.memory.reader;
    if let (Some(s), Some(e)) = (chunk_start_at(space, old), chunk_end_at(space, old)) {
        if (epoch_from_interval(s), epoch_end_from_interval(e)) == range {
            bail!(
                "memory {old:x} already spans {}",
                format_time_range(range.0, range.1)
            );
        }
    }
    let Some(summary_handle) = chunk_summary_handle(space, old) else {
        bail!(
            "memory {old:x} has no text summary; respanning an image memory is not supported yet"
        );
    };
    let summary: View<str> = reader
        .get(summary_handle)
        .context("read the memory's text")?;
    let lens = match chunk_lens_handle(space, old) {
        Some(handle) => {
            let lens: View<str> = reader.get(handle).context("read the memory's lens")?;
            Some(lens.as_ref().to_owned())
        }
        None => None,
    };
    let (mut fragment, moved) = memory_model::chunk_fragment(memory_model::ChunkDraft {
        content: memory_model::ChunkDraftContent::Text(summary.as_ref().to_owned()),
        start_at: clock::point(range.0)?,
        end_at: clock::point(range.1)?,
        lens,
        references: chunk_references(space, old).into_iter().collect(),
        about_exec_result: chunk_about_exec_result(space, old),
        about_archive_message: chunk_about_archive_message(space, old),
        observed_at: BTreeSet::from([clock::point(now)?]),
        aliases: BTreeSet::new(),
    })?;
    if moved == old {
        bail!(
            "memory {old:x} already spans {}",
            format_time_range(range.0, range.1)
        );
    }
    fragment += memory_model::respan_edge(moved, old);
    Ok((fragment, moved))
}

/// Parse one timestamp as people actually wrote them at the head of a memory:
/// `YYYY-MM-DDTHH:MM[:SS]`, a space instead of the `T`, a trailing `Z`, or a
/// `+HH:MM`/`-HH:MM` offset (converted to the bare form everyone else writes).
fn parse_written_stamp(raw: &str) -> Option<Epoch> {
    let raw = raw.trim();
    let bytes = raw.as_bytes();
    let (body, offset_secs): (&str, i64) = if let Some(body) = raw.strip_suffix('Z') {
        (body, 0)
    } else if raw.len() > 6
        && (bytes[raw.len() - 6] == b'+' || bytes[raw.len() - 6] == b'-')
        && bytes[raw.len() - 3] == b':'
    {
        let (body, off) = raw.split_at(raw.len() - 6);
        if !off.is_ascii() {
            return None;
        }
        let sign: i64 = if off.starts_with('-') { -1 } else { 1 };
        let hh: i64 = off[1..3].parse().ok()?;
        let mm: i64 = off[4..6].parse().ok()?;
        (body, sign * (hh * 3600 + mm * 60))
    } else {
        (raw, 0)
    };
    let mut body = body.replacen(' ', "T", 1);
    if body.len() == 16 && body.as_bytes()[13] == b':' {
        body.push_str(":00");
    }
    let epoch = parse_tai_timestamp(&body).ok()?;
    Some(epoch - Duration::from_seconds(offset_secs as f64))
}

/// What the head of a memory's text says about its span, if anything:
/// `A..B` or `A/B` with either stamp form above (a space between date and
/// time allowed), or a duration such as `10m` / `2h` meaning the stretch that
/// ended at the memory's stamp.
fn leading_range(text: &str, stamp: Epoch) -> Option<(Epoch, Epoch)> {
    let text = text.trim_start();
    // Up to four whitespace-separated tokens can carry `DATE TIME..DATE TIME`.
    let tokens: Vec<&str> = text.split_whitespace().take(4).collect();
    let first = *tokens.first()?;
    // A duration prefix.
    if let Some(number) = first
        .strip_suffix('m')
        .or_else(|| first.strip_suffix('h'))
        .or_else(|| first.strip_suffix('s'))
    {
        if let Ok(n) = number.parse::<f64>() {
            if n > 0.0 && tokens.len() > 1 {
                let unit = match first.chars().last()? {
                    'h' => 3600.0,
                    'm' => 60.0,
                    _ => 1.0,
                };
                return Some((stamp - Duration::from_seconds(n * unit), stamp));
            }
        }
    }
    let looks_like_date =
        |t: &str| t.len() >= 10 && t.as_bytes()[4] == b'-' && t.as_bytes()[7] == b'-';
    // Rejoin `DATE TIME` pairs so a range written with spaces still parses.
    let mut joined = String::new();
    let mut i = 0;
    while i < tokens.len() {
        let t = tokens[i];
        if looks_like_date(t) && t.len() == 10 && i + 1 < tokens.len() {
            joined.push_str(t);
            joined.push('T');
            joined.push_str(tokens[i + 1]);
            i += 2;
        } else {
            joined.push_str(t);
            i += 1;
        }
        if joined.contains("..") || joined.contains('/') {
            break;
        }
        joined.push(' ');
    }
    let head = joined.split_whitespace().next()?;
    if !looks_like_date(head) {
        return None;
    }
    let (a, b) = head.split_once("..").or_else(|| head.split_once('/'))?;
    let from = parse_written_stamp(a)?;
    let to = parse_written_stamp(b)?;
    (from < to).then_some((from, to))
}

/// `memory respan-instants [--dry-run]` -- give every zero-length memory the
/// span it should have had: the range its own text begins with, a duration
/// its text begins with, or else the moment ending at its stamp. An inverted
/// range is turned forward. Each becomes one respan; all of them are published
/// as one commit. Repeating it finds nothing to do.
fn respan_instants(storage: MemoryStorage<'_>, dry_run: bool, out: &mut Out<'_>) -> Result<()> {
    let loaded = storage.load()?;
    let space = &loaded.memory.facts;
    let reader = &loaded.memory.reader;
    let now = clock::now()?;
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    let mut examples = std::collections::BTreeMap::<&str, Vec<String>>::new();
    let mut batch = Fragment::empty();
    let mut planned = 0usize;
    for id in all_chunk_ids(space) {
        let (Some(s), Some(e)) = (chunk_start_at(space, id), chunk_end_at(space, id)) else {
            continue;
        };
        let (start, end) = (epoch_from_interval(s), epoch_end_from_interval(e));
        if start < end {
            continue;
        }
        let Some(summary_handle) = chunk_summary_handle(space, id) else {
            *counts.entry("image (skipped)").or_default() += 1;
            continue;
        };
        // Already respanned: a chunk with the same text supersedes it.
        let already = find!(
            n: Id,
            pattern!(space, [{ ?n @ metadata::tag: &crate::schemas::memory::KIND_CHUNK_ID, metadata::supersedes: id }])
        )
        .any(|n| chunk_summary_handle(space, n) == Some(summary_handle));
        if already {
            *counts.entry("already respanned").or_default() += 1;
            continue;
        }
        let text: View<str> = reader.get(summary_handle).context("read a memory's text")?;
        let (category, range) = if start > end {
            ("inverted, turned forward", (end, start))
        } else if let Some(range) = leading_range(text.as_ref(), start) {
            // A range in the text nowhere near the stamp is a quotation, not a
            // claim about this memory: give it a moment and list it for review.
            let near = |t: Epoch| (t - start).abs() < Duration::from_days(2.0);
            if near(range.0) || near(range.1) {
                ("range in its own text", range)
            } else {
                (
                    "far-off range in text (given a moment; review)",
                    (start - moment(), start),
                )
            }
        } else {
            ("a moment ending at the stamp", (start - moment(), start))
        };
        *counts.entry(category).or_default() += 1;
        let shown = examples.entry(category).or_default();
        if shown.len() < 3 {
            let head: String = text.as_ref().chars().take(70).collect();
            shown.push(format!(
                "  {:x} {} -> {}  {:?}",
                id,
                format_time_range(start, end),
                format_time_range(range.0, range.1),
                head
            ));
        }
        if !dry_run {
            let (fragment, _) = respan_fragment(&loaded, id, range, now)?;
            batch += fragment;
        }
        planned += 1;
    }
    for (category, n) in &counts {
        out.line(format!("{n:>6}  {category}"))?;
        for line in examples.get(category).into_iter().flatten() {
            out.line(format!("{line}"))?;
        }
    }
    if dry_run {
        out.line(format!(
            "dry run: {planned} respan(s) would be written as one commit"
        ))?;
        return Ok(());
    }
    if planned == 0 {
        out.line(format!("nothing to do"))?;
        return Ok(());
    }
    storage.publish_memory(batch)?;
    out.line(format!("{planned} respan(s) written as one commit"))?;
    Ok(())
}

/// `memory respan-seams [--dry-run]` -- close the seams between arcs written
/// with rounded edges. An arc that ends "through 23:59:59" or "through hh:mm"
/// and the next memory that starts one second or one minute later leave a
/// sliver of time nobody lived through uncovered, and the cover, which is
/// coarser further back and complete by construction, fills each sliver with
/// the widest memory over it: a whole-life root paragraph for one second.
/// Extending the arc to the next start is a coordinate correction with the
/// text unchanged, so it is a respan. Only arcs an hour or wider, only gaps
/// of a minute or less, one commit; a second run finds nothing.
fn respan_seams(storage: MemoryStorage<'_>, dry_run: bool, out: &mut Out<'_>) -> Result<()> {
    let loaded = storage.load()?;
    let space = &loaded.memory.facts;
    let now = clock::now()?;
    let spans = collect_chunk_spans(space);
    let mut starts: Vec<i128> = spans.iter().map(|s| s.0).collect();
    starts.sort_unstable();
    starts.dedup();
    let hour: i128 = 3_600 * 1_000_000_000;
    let minute: i128 = 60 * 1_000_000_000;
    let mut batch = Fragment::empty();
    let mut planned = Vec::new();
    for &(start, end, id) in &spans {
        if end - start < hour {
            continue;
        }
        let next = match starts.binary_search(&end) {
            Ok(k) => starts.get(k + 1).copied(),
            Err(k) => starts.get(k).copied(),
        };
        let Some(next) = next else { continue };
        if next <= end || next - end > minute {
            continue;
        }
        let range = (key_to_epoch(start), key_to_epoch(next));
        planned.push((
            id,
            format_time_range(key_to_epoch(start), key_to_epoch(end)),
            format_time_range(range.0, range.1),
        ));
        if !dry_run {
            let (fragment, _) = respan_fragment(&loaded, id, range, now)?;
            batch += fragment;
        }
    }
    for (id, from, to) in planned.iter().take(12) {
        out.line(format!("  {id:x} {from} -> {to}"))?;
    }
    if planned.len() > 12 {
        out.line(format!("  ... {} more", planned.len() - 12))?;
    }
    if dry_run {
        out.line(format!(
            "dry run: {} seam(s) would be closed as one commit",
            planned.len()
        ))?;
        return Ok(());
    }
    if planned.is_empty() {
        out.line(format!("nothing to do"))?;
        return Ok(());
    }
    storage.publish_memory(batch)?;
    out.line(format!("{} seam(s) closed as one commit", planned.len()))?;
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

    let start_at = clock::point(range.0)?;
    let end_at = clock::point(range.1)?;
    let observed_at = clock::point(observed_at)?;
    let (fragment, chunk_id) = memory_model::chunk_fragment(memory_model::ChunkDraft {
        content: memory_model::ChunkDraftContent::Text(summary_text.to_owned()),
        start_at,
        end_at,
        lens: lens.map(str::to_owned),
        references: reference_ids,
        about_exec_result: None,
        about_archive_message: None,
        observed_at: BTreeSet::from([observed_at]),
        aliases: BTreeSet::new(),
    })?;
    storage.publish_memory(fragment)?;
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

/// Store image bytes as a blob and create a wordless image chunk at `range`.
/// Mirrors `create_chunk`, but the content is the picture (`ctx::image`) rather
/// than a summary — temporal containment (the only hierarchy) still relates it
/// to text chunks by time, and `[caption](memory:<hex>)` references still point
/// at it like any chunk.
fn create_image_chunk(
    storage: MemoryStorage<'_>,
    bytes: &[u8],
    range: (Epoch, Epoch),
) -> Result<Id> {
    let start_at = clock::point(range.0)?;
    let end_at = clock::point(range.1)?;
    let observed_at = clock::point(range.1)?;
    let (fragment, chunk_id) = memory_model::chunk_fragment(memory_model::ChunkDraft {
        content: memory_model::ChunkDraftContent::Image(bytes.to_vec()),
        start_at,
        end_at,
        lens: None,
        references: BTreeSet::new(),
        about_exec_result: None,
        about_archive_message: None,
        observed_at: BTreeSet::from([observed_at]),
        aliases: BTreeSet::new(),
    })?;
    storage.publish_memory(fragment)?;
    Ok(chunk_id)
}

// ---------------------------------------------------------------------------
// consolidate + replay — the comb verbs
// ---------------------------------------------------------------------------

const CONSOLIDATE_STREAM: &str = "consolidate-edge";
const MEMORY_REPLAY_STREAM: &str = "memory-replay";

fn comb_advance(
    storage: MemoryStorage<'_>,
    loaded: &LoadedComb,
    stream: &str,
    persona: &str,
    position: Option<Epoch>,
    grain: Option<&str>,
) -> Result<()> {
    let now = clock::now()?;
    let position = position.map(clock::point).transpose()?;
    let observed_at = clock::point(now)?;
    let comb = &loaded.comb.facts;
    let predecessors = comb_model::resolution(comb, stream, persona)?
        .map(|resolution| resolution.head_ids())
        .unwrap_or_default()
        .into_iter()
        .collect();
    let (fragment, _) = comb_model::cursor_fragment(comb_model::CursorDraft {
        stream: stream.to_owned(),
        persona: persona.to_owned(),
        position,
        anchor: None,
        grain: grain.map(str::to_owned),
        predecessors,
        observed_at: BTreeSet::from([observed_at]),
    })?;
    storage.publish_comb(fragment)
}

/// `memory consolidate start <ts> | stop | <ts> <summary...>`
///
/// The consolidation edge is where the next chunk opens. `<ts> <summary>`
/// writes a chunk spanning [edge, ts] and advances the edge to ts — the
/// boundary is chosen in hindsight (you pass the timestamp where the shift
/// happened, typically copied from replay output; the shift-signaling
/// message becomes the next chunk's opening).

/// Parse a grain like "90m", "2h", "1d", "4w" into nanoseconds.
fn parse_grain(s: &str) -> Result<i128> {
    let split = s
        .char_indices()
        .next_back()
        .map(|(index, _)| index)
        .ok_or_else(|| anyhow!("grain must be a positive duration like 2h"))?;
    let (num, unit) = s.split_at(split);
    let n: i128 = num.parse().with_context(|| format!("invalid grain: {s}"))?;
    if n <= 0 {
        bail!("grain must be positive: {s}");
    }
    let ns_per = match unit {
        "m" => 60_i128 * 1_000_000_000,
        "h" => 3_600_i128 * 1_000_000_000,
        "d" => 86_400_i128 * 1_000_000_000,
        "w" => 7 * 86_400_i128 * 1_000_000_000,
        _ => bail!("grain unit must be m/h/d/w: {s}"),
    };
    n.checked_mul(ns_per)
        .ok_or_else(|| anyhow!("grain is too large: {s}"))
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
/// journal chunks whose span-width fits the grain. This is how upper
/// layers get written — replay the layer below, consolidate up. Reads ALL
/// chunks regardless of which session wrote them: one being, one memory.

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
fn lens(storage: MemoryStorage<'_>, theme: Option<&str>, out: &mut Out<'_>) -> Result<()> {
    let filter = theme.map(str::to_lowercase);
    let loaded = storage.load()?;
    let space = &loaded.memory.facts;
    let mut lenses: Vec<(String, i128, i128, Id)> = Vec::new();
    for id in all_chunk_ids(space) {
        let Some(lh) = chunk_lens_handle(space, id) else {
            continue;
        };
        let theme: String = loaded
            .memory
            .reader
            .get::<View<str>, UTF8String>(lh)
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
        out.line(format!(
            "no lens memories{} — create one with `memory create --lens <theme> <from>..<to> <summary>`",
            filter.map(|t| format!(" matching \"{t}\"")).unwrap_or_default()
        ))?;
        return Ok(());
    }

    if filter.is_some() {
        for (theme, s, e, id) in &lenses {
            out.line(format!(
                "\n## [{theme}] {}  ({id:x})",
                format_time_range(key_to_epoch(*s), key_to_epoch(*e))
            ))?;
            if let Some(h) = chunk_summary_handle(space, *id) {
                let summary: View<str> =
                    loaded.memory.reader.get(h).context("read lens summary")?;
                out.line(format!("{}", summary.trim_end()))?;
            }
        }
    } else {
        out.line(format!("{} lens memor(ies):", lenses.len()))?;
        for (theme, s, e, id) in &lenses {
            let first = chunk_summary_handle(space, *id)
                .and_then(|h| loaded.memory.reader.get::<View<str>, UTF8String>(h).ok())
                .map(|v| v.as_ref().lines().next().unwrap_or("").to_string())
                .unwrap_or_default();
            out.line(format!(
                "  [{theme}] {}  ({id:x})  {first}",
                format_time_range(key_to_epoch(*s), key_to_epoch(*e))
            ))?;
        }
    }
    Ok(())
}

/// `memory list [<grain>]` — show the SHAPE of the memory as time-ranges only,
/// never content (coverage is by time range, not by reference). With a grain,
/// lists the maximal journal chunks whose width fits that zoom — the
/// same layer `replay <grain>` would stream. Without a grain, prints every
/// journal chunk as a containment outline: indentation expresses how
/// wider ranges cover narrower ones.
fn list(storage: MemoryStorage<'_>, grain: Option<&str>, out: &mut Out<'_>) -> Result<()> {
    let grain: Option<(String, i128)> = match grain {
        Some(raw) => Some((raw.to_owned(), parse_grain(raw)?)),
        None => None,
    };
    let loaded = storage.load()?;
    let mut chunks = collect_chunk_spans(&loaded.memory.facts);
    if chunks.is_empty() {
        out.line(format!("no memory chunks"))?;
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
            out.line(format!(
                "layer at grain {raw}: {} chunk(s) of {} total",
                layer.len(),
                chunks.len()
            ))?;
            for (s, e, id) in &layer {
                out.line(format!(
                    "  {}  [{}]  ({:x})",
                    format_time_range(key_to_epoch(*s), key_to_epoch(*e)),
                    humanize_ns(e - s),
                    id
                ))?;
            }
        }
        None => {
            // Containment outline: containers before contained; indent by
            // how many strictly-wider chunks contain this one.
            chunks.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
            out.line(format!(
                "{} chunk(s) (indent = containment by time range)",
                chunks.len()
            ))?;
            for (s, e, id) in &chunks {
                let depth = chunks
                    .iter()
                    .filter(|(os, oe, oid)| oid != id && os <= s && oe >= e && (oe - os) > (e - s))
                    .count();
                let indent = "  ".repeat(depth + 1);
                out.line(format!(
                    "{indent}{}  ({:x})",
                    format_time_range(key_to_epoch(*s), key_to_epoch(*e)),
                    id
                ))?;
            }
        }
    }
    Ok(())
}

/// `memory churn` replays density-shaped recollection over the journal's
/// observation history. The fixed step is diagnostic cadence only; it is not a
/// boundary or quantisation in the selector.
fn churn(storage: MemoryStorage<'_>, opts: &ChurnOptions, out: &mut Out<'_>) -> Result<()> {
    let ChurnOptions {
        budget_chars: budget,
        steps,
        step_units,
    } = *opts;
    let loaded = storage.load()?;
    let rows = crate::memory_cover::replay_cover(
        &loaded.memory.facts,
        &loaded.memory.reader,
        budget,
        0,
        steps,
        step_units,
    )?;
    if rows.is_empty() {
        out.line(format!("no memory chunks"))?;
        return Ok(());
    }

    out.line(format!(
        "{:<20} {:<20} {:>6} {:>9} {:>7} {:>7} {:>9}",
        "observed", "memory edge", "chunks", "used", "fill%", "kept%", "reread"
    ))?;
    let mut rereads = Vec::new();
    let mut deep = 0usize;
    let mut silent_steps = 0usize;
    for (k, r) in rows.iter().enumerate() {
        let reread = r.used.saturating_sub(r.kept);
        let fill_pct = if budget == 0 {
            0.0
        } else {
            100.0 * r.used as f64 / budget as f64
        };
        let kept_pct = if r.prev_used == 0 {
            0.0
        } else {
            100.0 * r.kept as f64 / r.prev_used as f64
        };
        if k > 0 {
            rereads.push(reread);
            if r.used > 0 && reread * 4 > r.used {
                deep += 1;
            }
        }
        let mut note = String::new();
        if !r.silent_life_quarters.is_empty() {
            silent_steps += 1;
            let stretches: Vec<String> = r
                .silent_life_quarters
                .iter()
                .map(|&(a, b)| format_time_range(key_to_epoch(a), key_to_epoch(b)))
                .collect();
            note.push_str(&format!("  SILENT > LIFE/4: {}", stretches.join(", ")));
        }
        if let Some((a, b)) = r.changed_at {
            note.push_str(&format!(
                "  changed from {}",
                format_time_range(key_to_epoch(a), key_to_epoch(b))
            ));
        }
        out.line(format!(
            "{:<20} {:<20} {:>6} {:>9} {:>6.1}% {:>6.1}% {:>9}{}",
            fmt_epoch(key_to_epoch(r.observed_now)),
            fmt_epoch(key_to_epoch(r.semantic_now)),
            r.chunks,
            r.used,
            fill_pct,
            kept_pct,
            if k == 0 { 0 } else { reread },
            note,
        ))?;
    }

    rereads.sort_unstable();
    let median = rereads.get(rereads.len() / 2).copied().unwrap_or(0);
    let max = rereads.last().copied().unwrap_or(0);
    let total: usize = rereads.iter().sum();
    let unobserved = rows.last().map_or(0, |row| row.unobserved_classes);
    out.line(format!(
        "{} transition(s) of {} quantum(s): re-rendered median {} chars, max {}, total {}; {} transition(s) re-rendered more than a quarter; {} step(s) had a silent stretch > LIFE/4; {} class(es) used range-end fallback for missing observation time",
        rereads.len(),
        step_units,
        median,
        max,
        total,
        deep,
        silent_steps,
        unobserved,
    ))?;
    Ok(())
}

fn check(storage: MemoryStorage<'_>, grain_raw: &str, out: &mut Out<'_>) -> Result<()> {
    let grain_ns = parse_grain(grain_raw)?;
    let loaded = storage.load()?;
    let all = collect_chunk_spans(&loaded.memory.facts);
    if all.is_empty() {
        out.line(format!("no memory chunks"))?;
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

    out.line(format!(
        "extent {}  ({} chunk(s) of width <= {grain_raw})",
        format_time_range(key_to_epoch(global_start), key_to_epoch(global_end)),
        covering.len()
    ))?;
    if gaps.is_empty() {
        out.line(format!(
            "OK no gaps >= {grain_raw} — coverage is contiguous at this zoom"
        ))?;
    } else {
        out.line(format!("{} gap(s) at grain {grain_raw}:", gaps.len()))?;
        for (s, e) in &gaps {
            out.line(format!(
                "  GAP {}  ({})",
                format_time_range(key_to_epoch(*s), key_to_epoch(*e)),
                humanize_ns(e - s)
            ))?;
        }
    }
    Ok(())
}

/// `memory density [<grain>]` — inspection tooling that finds where the
/// containment hierarchy is BUSHY: a span with many direct *leaf* children and
/// no intermediate arc summary combing them into mid-level groups. That is a
/// useful journal-maintenance signal: a middle-scale narrative may be missing,
/// even though density-shaped recollection can freely sample the leaves. This
/// diagnostic does not drive or constrain recollection and writes nothing.
/// Optional `<grain>` restricts the report to spans of width <= grain.
fn density(storage: MemoryStorage<'_>, grain: Option<&str>, out: &mut Out<'_>) -> Result<()> {
    // Threshold for the BUSHY flag: this many direct leaf-children with no
    // intermediate arc make a span expensive to expand in the cover.
    const BUSHY_LEAVES: usize = 5;
    let grain_ns: Option<i128> = match grain {
        Some(raw) => Some(parse_grain(raw)?),
        None => None,
    };
    let loaded = storage.load()?;
    let spans = collect_chunk_spans(&loaded.memory.facts);
    if spans.is_empty() {
        out.line(format!("no memory chunks"))?;
        return Ok(());
    }
    let n = spans.len();

    // A diagnostic containment projection only: recollection itself has no
    // parent/child structure. A chunk's diagnostic parent is the tightest
    // strictly-wider chunk that spans it.
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
    out.line(format!(
        "memory density — {n} chunk(s), {total_forks} fork(s) (>=2 children){}",
        grain
            .map(|raw| format!(" of width <= {raw}"))
            .unwrap_or_default(),
    ))?;
    out.line(format!(
            "  BUSHY = >= {BUSHY_LEAVES} direct leaf-children with no intermediate arc (expensive to expand → comb leaves into arcs); {bushy_count} found"
        ))?;
    if forks.is_empty() {
        out.line(format!("  (no forks at this zoom)"))?;
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

    out.line(format!("\nBushiest forks (worst first):"))?;
    for &i in forks.iter().take(15) {
        out.line(format!("  {}", render(i)))?;
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
    out.line(format!(
        "\nRecent edge (forks starting within 2w, newest first):"
    ))?;
    if recent.is_empty() {
        out.line(format!("  (none)"))?;
    } else {
        for &i in &recent {
            out.line(format!("  {}", render(i)))?;
        }
    }
    Ok(())
}

fn meta(storage: MemoryStorage<'_>, raw: &str, out: &mut Out<'_>) -> Result<()> {
    let loaded = storage.load_provenance()?;
    let memory = &loaded.memory;
    let space = &memory.memory.facts;
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
        out.line(format!(
            "range: {}",
            format_time_range(epoch_from_interval(start_v), epoch_end_from_interval(end_v))
        ))?;
    }
    out.line(format!("id: {chunk_id:x}"))?;
    let written: Vec<String> = chunk_observed_at(space, chunk_id)
        .into_iter()
        .map(|at| fmt_epoch(epoch_from_interval(at)))
        .collect();
    if !written.is_empty() {
        out.line(format!("written_at: {}", written.join(", ")))?;
    }
    // Read-only history. A retraction record or a `supersedes` edge from the
    // old comb is evidence of what was once done; the journal gives neither
    // any ordering or visibility meaning (memories coexist).
    let span_of = |id: Id| match (chunk_start_at(space, id), chunk_end_at(space, id)) {
        (Some(s), Some(e)) => format!(
            "{} ({:x})",
            format_time_range(epoch_from_interval(s), epoch_end_from_interval(e)),
            id
        ),
        _ => format!("{id:x}"),
    };
    let retractions: Vec<Id> = find!(
        r: Id,
        pattern!(space, [{ ?r @ metadata::tag: &crate::schemas::memory::KIND_RETRACTION, metadata::supersedes: chunk_id }])
    )
    .collect();
    if !retractions.is_empty() {
        out.line(format!(
            "retraction_records: {} (historical; the journal shows every memory)",
            retractions
                .iter()
                .map(|id| format!("{id:x}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))?;
    }
    let edges_out: Vec<Id> =
        find!(o: Id, pattern!(space, [{ chunk_id @ metadata::supersedes: ?o }])).collect();
    if !edges_out.is_empty() {
        out.line(format!(
            "supersedes: {} (a respan when the text is identical)",
            edges_out
                .iter()
                .map(|id| span_of(*id))
                .collect::<Vec<_>>()
                .join(", ")
        ))?;
    }
    let edges_in: Vec<Id> = find!(
        n: Id,
        pattern!(space, [{ ?n @ metadata::tag: &crate::schemas::memory::KIND_CHUNK_ID, metadata::supersedes: chunk_id }])
    )
    .collect();
    if !edges_in.is_empty() {
        out.line(format!(
            "superseded_by: {} (a respan when the text is identical)",
            edges_in
                .iter()
                .map(|id| span_of(*id))
                .collect::<Vec<_>>()
                .join(", ")
        ))?;
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
        out.line(format!("references: {}", refs.join(", ")))?;
    }
    let incoming: Vec<Id> =
        find!(s: Id, pattern!(space, [{ ?s @ ctx::reference: chunk_id }])).collect();
    if !incoming.is_empty() {
        out.line(format!(
            "referenced_by: {}",
            incoming
                .iter()
                .map(|id| format!("{id:x}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))?;
    }
    if let Some(exec_id) = chunk_about_exec_result(space, chunk_id) {
        out.line(format!("about_exec_result: {exec_id:x}"))?;
    }
    if let Some(archive_id) = chunk_about_archive_message(space, chunk_id) {
        out.line(format!("about_archive_message: {archive_id:x}"))?;
        print_archive_meta(
            &loaded.archive.reader,
            &loaded.archive.facts,
            archive_id,
            out,
        )?;
    }
    Ok(())
}

fn print_archive_meta<P: TriblePattern>(
    reader: &PileSnapshot,
    archive: &P,
    archive_msg_id: Id,
    out: &mut Out<'_>,
) -> Result<()> {
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
        out.line(format!("  projects_to: {block:x}"))?;
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
        out.line(format!("  author: {author:x}"))?;
    }
    if let Some((handle,)) = find!(
        (handle: Inline<Handle<UTF8String>>),
        pattern!(archive, [{
            archive_msg_id @ archive_schema::source_projection::raw_author: ?handle,
        }])
    )
    .next()
    {
        native_projection = true;
        let value: View<str> = reader.get(handle).context("read Archive raw author")?;
        out.line(format!("  raw_author: {}", value.as_ref()))?;
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
        out.line(format!("  source_namespace: {namespace:x}"))?;
    }
    if let Some((handle,)) = find!(
        (handle: Inline<Handle<UTF8String>>),
        pattern!(archive, [{
            archive_msg_id @ archive_schema::source_projection::source_locator: ?handle,
        }])
    )
    .next()
    {
        native_projection = true;
        let value: View<str> = reader.get(handle).context("read Archive source locator")?;
        out.line(format!("  source_locator: {}", value.as_ref()))?;
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
            out.line(format!("  legacy_author: {author:x}"))?;
        }
        if let Some(handle) = find!(
            handle: Inline<Handle<UTF8String>>,
            pattern!(archive, [{ archive_msg_id @ legacy_archive_schema::author_name: ?handle }])
        )
        .next()
        {
            let value: View<str> = reader
                .get(handle)
                .context("read legacy Archive author name")?;
            out.line(format!("  legacy_author_name: {}", value.as_ref()))?;
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
fn find_archive_in_range<P: TriblePattern>(
    catalog: &P,
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
fn provenance(storage: MemoryStorage<'_>, chunk_arg: &str, out: &mut Out<'_>) -> Result<()> {
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

    out.line(format!("chunk: {chunk_id:x}"))?;
    out.line(format!(
        "range: {}..{}",
        fmt_epoch(start_epoch),
        fmt_epoch(end_epoch),
    ))?;

    let execs =
        cognition_model::exec_results_in_range(&loaded.cognition.facts, start_epoch, end_epoch);
    out.line(format!(
        "\ncognition exec results in range: {}",
        execs.len()
    ))?;
    for (id, t) in execs {
        let (epoch, _): (Epoch, Epoch) = t.try_from_inline().unwrap();
        out.line(format!("  {id:x}  {}", fmt_epoch(epoch)))?;
    }

    let projections = find_archive_in_range(&loaded.archive.facts, start_epoch, end_epoch);
    out.line(format!(
        "\narchive projections in range: {}",
        projections.len()
    ))?;
    for (id, t) in projections {
        let (epoch, _): (Epoch, Epoch) = t.try_from_inline().unwrap();
        out.line(format!("  {id:x}  {}", fmt_epoch(epoch)))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// show / turn subcommands
// ---------------------------------------------------------------------------

fn print_chunk<P: TriblePattern>(
    reader: &PileSnapshot,
    space: &P,
    chunk_id: Id,
    out: &mut Out<'_>,
) -> Result<()> {
    if let Some(handle) = chunk_summary_handle(space, chunk_id) {
        let summary: View<str> = reader.get(handle).context("read chunk summary")?;
        return out.line(summary.trim_end());
    }
    if let Some(handle) = chunk_image_handle(space, chunk_id) {
        out.line(format!(
            "[image memory @ {}]",
            chunk_span_str(space, chunk_id)
        ))?;
        return emit_image(reader, handle, out);
    }
    bail!("chunk {chunk_id:x} has no summary or image")
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn resolve_chunk_id(loaded: &LoadedMemory, raw: &str) -> Result<Id> {
    let prefix = normalize_prefix(raw)?;
    let space = &loaded.memory.facts;

    // Entity ids and historical aliases are both stable names for one
    // immutable episode. Resolve them into target ids before deciding
    // ambiguity, so an id that is also recorded as its own alias still
    // denotes one chunk. No lookup depends on how the id was minted.
    let mut chunk_matches = BTreeSet::new();
    for chunk_id in all_chunk_ids(&loaded.memory.facts) {
        if id_starts_with(chunk_id, prefix.as_str()) {
            chunk_matches.insert(chunk_id);
        }
    }
    // Aliases are annotation, so ask for them per chunk rather than
    // materialising every row. A prefix resolve is a rare path and each lookup
    // is an index probe.
    for chunk_id in all_chunk_ids(&loaded.memory.facts) {
        if chunk_aliases(&loaded.memory.facts, chunk_id)
            .into_iter()
            .any(|alias| id_starts_with(alias, prefix.as_str()))
        {
            chunk_matches.insert(chunk_id);
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

fn print_turn_facets<P: TriblePattern>(
    reader: &PileSnapshot,
    space: &P,
    raw: &str,
    out: &mut Out<'_>,
) -> Result<()> {
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

    out.line(format!(
        "turn {} has {} memory facet(s)",
        fmt_id(first_turn),
        chunk_ids.len()
    ))?;
    for (i, chunk_id) in chunk_ids.iter().enumerate() {
        if i > 0 {
            out.line("")?;
        }
        print_chunk(reader, space, *chunk_id, out)?;
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

impl Memory {
    pub fn consolidate(&self, persona: &str, until: Epoch, summary: &str) -> Result<CreatedMemory> {
        require_persona(persona)?;
        if summary.is_empty() {
            bail!("consolidation summary must not be empty");
        }
        let storage = self.storage();
        let loaded = storage.load_comb()?;
        let Some(resolution) =
            comb_model::resolution(&loaded.comb.facts, CONSOLIDATE_STREAM, persona)?
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
                fmt_epoch(until),
                fmt_epoch(edge)
            );
        }
        // The boundary timestamp is a deterministic observation for
        // this automatic write, so retrying a half-completed
        // Memory-then-Comb publication yields the same Memory data.
        let chunk_id = create_chunk(storage, &loaded.memory, summary, (edge, until), None, until)?;
        comb_advance(
            storage,
            &loaded,
            CONSOLIDATE_STREAM,
            persona,
            Some(until),
            None,
        )?;

        Ok(CreatedMemory {
            id: chunk_id,
            start: edge,
            end: until,
        })
    }
    /// Deliver one coordinate-complete batch before advancing the cursor.
    /// If Out rejects the batch payload, the cursor does not move. The final
    /// cursor-status line is emitted only after publication succeeds.
    pub fn replay(&self, persona: &str, count: usize, out: &mut Out<'_>) -> Result<()> {
        require_persona(persona)?;
        if count == 0 {
            bail!("memory replay batch count must be greater than zero");
        }
        let storage = self.storage();
        let loaded = storage.load_comb()?;
        let Some(resolution) =
            comb_model::resolution(&loaded.comb.facts, MEMORY_REPLAY_STREAM, persona)?
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

        // Chunks at this zoom: width fits the grain and is maximal among
        // grain-fitting chunks (not contained in a
        // wider one that also fits — that one IS this zoom's voice).
        let mut fitting: Vec<(i128, i128, Id)> = Vec::new();
        for chunk_id in all_chunk_ids(space) {
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
            out.line(format!(
                "memory replay complete at grain {grain_raw}: nothing after the cursor."
            ))?;
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
            out.line(format!(
                "── {} ({:x})",
                format_time_range(key_to_epoch(*sk), key_to_epoch(*ek)),
                chunk_id
            ))?;
            out.line(format!("{summary}"))?;
            out.line("")?;
            last_start = *sk;
        }
        comb_advance(
            storage,
            &loaded,
            MEMORY_REPLAY_STREAM,
            persona,
            Some(key_to_epoch(last_start)),
            Some(grain_raw),
        )?;
        out.line(format!(
            "— batch: {take} chunk(s) at grain {grain_raw}; {} remaining",
            total - take
        ))?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::super::cli_cover::*;
    use super::*;
    use std::fs::File;

    struct TestPile {
        pile: PathBuf,
        key: PathBuf,
        storage: crate::storage::Storage,
    }

    impl TestPile {
        fn new() -> Self {
            let pile =
                std::env::temp_dir().join(format!("faculties-memory-cover-{}.pile", ufoid().id));
            let key = pile.with_extension("key");
            File::create(&pile).expect("create test pile");
            crate::storage::initialize_signer(&pile, Some(&key)).expect("initialize test signer");
            Self {
                storage: crate::storage::Storage::new(pile.clone(), Some(key.clone())),
                pile,
                key,
            }
        }

        fn storage(&self) -> MemoryStorage<'_> {
            MemoryStorage {
                storage: &self.storage,
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
        let (fragment, id) = memory_model::chunk_fragment(draft).expect("build Memory chunk");
        storage
            .publish_memory(fragment)
            .expect("publish Memory chunk");
        id
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
    fn historical_aliases_resolve_to_their_exact_episode() {
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
        let scores = crate::memory_cover::lexical_relevance_scores(
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
        // Seed a coarse apex over two fine day-chunks: enough space lets the
        // density sampler recall both scales without making either mandatory.
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
        let cover =
            build_context_cover(&loaded, 10_000, 0, None, None, None, DEFAULT_SIM_THRESHOLD)
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

    fn seed_cover_cost_fixture(pile: &TestPile) -> LoadedContext {
        let storage = pile.storage();
        publish_chunk(
            storage,
            text_draft("root", "2026-05-01T00:00:00", "2026-05-03T00:00:00"),
        );
        publish_chunk(
            storage,
            text_draft("one", "2026-05-01T00:00:00", "2026-05-02T00:00:00"),
        );
        publish_chunk(
            storage,
            text_draft("two", "2026-05-02T00:00:00", "2026-05-03T00:00:00"),
        );
        storage.load_context(false).expect("load cost fixture")
    }

    #[test]
    fn render_report_preserves_legacy_cover_bytes_at_charged_boundaries() {
        let pile = TestPile::new();
        let loaded = seed_cover_cost_fixture(&pile);
        for budget in [0, 47, 48, 139, 145, 1000] {
            for overhead in [0, 2, 50] {
                let mut options = CoverOpts::plain(budget);
                options.chunk_overhead = overhead;
                let report = render_context(&loaded, &options).unwrap();
                let old_entrypoint = crate::memory_cover::render_cover(
                    &loaded.memory.memory.facts,
                    &TribleSet::new(),
                    &loaded.memory.memory.reader,
                    &options,
                )
                .unwrap();
                assert_eq!(report.text, old_entrypoint);
                assert!(!report.text.contains("memory context —"));
                assert_eq!(report.diagnostics.len(), 1);
            }
        }
    }

    #[test]
    fn chunk_overhead_can_keep_an_otherwise_affordable_split_coarse() {
        let pile = TestPile::new();
        let loaded = seed_cover_cost_fixture(&pile);

        // Rendered costs include 43 framing characters: root=47 and each
        // child=46. A budget of 139 admits all three candidates.
        let intrinsic =
            build_context_cover(&loaded, 139, 0, None, None, None, DEFAULT_SIM_THRESHOLD)
                .expect("intrinsic recollection");
        assert!(intrinsic.contains("root"));
        assert!(intrinsic.contains("one"));
        assert!(intrinsic.contains("two"));

        // Charging fifty per selected chunk makes root=97 and each child=96,
        // so the same budget has only 42 characters of sampling space.
        let charged =
            build_context_cover(&loaded, 139, 50, None, None, None, DEFAULT_SIM_THRESHOLD)
                .expect("charged recollection");
        assert!(charged.contains("root"));
        assert!(!charged.contains("one"));
        assert!(!charged.contains("two"));
    }

    #[test]
    fn chunk_overhead_is_charged_once_per_selected_chunk_at_exact_boundaries() {
        let pile = TestPile::new();
        let loaded = seed_cover_cost_fixture(&pile);

        // The best first memory costs root(47) + one overhead(2) = 49. Below
        // that boundary the greedy walk stops without violating the budget.
        let below_first =
            build_context_cover(&loaded, 48, 2, None, None, None, DEFAULT_SIM_THRESHOLD)
                .expect("an empty in-budget recollection");
        assert!(below_first.is_empty());

        // The root plus both children costs 49 + 48 + 48 = 145.
        let exact = build_context_cover(&loaded, 145, 2, None, None, None, DEFAULT_SIM_THRESHOLD)
            .expect("exact charged split");
        assert!(exact.contains("root"));
        assert!(exact.contains("one"));
        assert!(exact.contains("two"));
    }

    fn rendered_ranges(cover: &str) -> Vec<&str> {
        cover
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("2026-") && line.contains(".."))
            .collect()
    }

    /// Context may recall a different account of the exact same moment, but it
    /// must not turn the moment into a different autobiography. This exercises
    /// both halves of that invariant end-to-end:
    ///
    /// - exact-span alternatives collapse to one structural position;
    /// - choosing a differently-sized, query-relevant alternative leaves every
    ///   selected temporal range unchanged across binding and non-binding
    ///   budgets.
    #[test]
    fn about_only_selects_within_equal_span_positions() {
        let pile = TestPile::new();
        let storage = pile.storage();
        let write = |summary: &str, start: &str, end: &str| {
            publish_chunk(storage, text_draft(summary, start, end))
        };

        write("root", "2026-06-01T00:00:00", "2026-06-05T00:00:00");
        let amber = "amber ".repeat(3);
        let cobalt = "cobalt ".repeat(10);
        let amber_id = write(&amber, "2026-06-01T00:00:00", "2026-06-03T00:00:00");
        let cobalt_id = write(&cobalt, "2026-06-01T00:00:00", "2026-06-03T00:00:00");
        write(
            &"recent ".repeat(10),
            "2026-06-03T00:00:00",
            "2026-06-05T00:00:00",
        );
        for (summary, start, end) in [
            (
                "old-left ".repeat(14),
                "2026-06-01T00:00:00",
                "2026-06-02T00:00:00",
            ),
            (
                "old-right ".repeat(14),
                "2026-06-02T00:00:00",
                "2026-06-03T00:00:00",
            ),
            (
                "new-left ".repeat(14),
                "2026-06-03T00:00:00",
                "2026-06-04T00:00:00",
            ),
            (
                "new-right ".repeat(14),
                "2026-06-04T00:00:00",
                "2026-06-05T00:00:00",
            ),
        ] {
            write(&summary, start, end);
        }

        let loaded = storage.load_context(false).expect("load cover fixture");
        let (query, contextual_summary, plain_summary) = if amber_id < cobalt_id {
            ("cobalt", cobalt.as_str(), amber.as_str())
        } else {
            ("amber", amber.as_str(), cobalt.as_str())
        };
        let render = |about| {
            build_context_cover(&loaded, 10_000, 0, about, None, None, DEFAULT_SIM_THRESHOLD)
                .expect("render cover")
        };

        // With enough room the equal-span position is recalled. The plain
        // projection deterministically selects the least-id account and
        // context substitutes the relevant account without moving the range.
        let plain = render(None);
        let contextual = render(Some(query));
        assert_eq!(rendered_ranges(&plain), rendered_ranges(&contextual));
        assert!(plain.contains(plain_summary.trim_end()));
        assert!(!plain.contains(contextual_summary.trim_end()));
        assert!(contextual.contains(contextual_summary.trim_end()));
        assert!(!contextual.contains(plain_summary.trim_end()));
    }
}
