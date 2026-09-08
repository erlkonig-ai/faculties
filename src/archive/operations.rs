//! Direct Archive operations over frozen canonical block-DAG observations.
//! Resident imports never open source names or attachment keys as host paths.

#[derive(Clone, Debug)]
pub struct Archive {
    pile: PathBuf,
    key: Option<PathBuf>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportSource {
    Agy,
    ChatGpt,
    ClaudeCode,
    ClaudeWeb,
    Codex,
    Copilot,
    Gemini,
}
#[derive(Clone, Debug)]
pub enum ImportSummary {
    Agy(AgyProjectionSummary),
    ChatGpt(ChatGptProjectionSummary),
    ClaudeCode(ClaudeCodeProjectionSummary),
    ClaudeWeb(ClaudeWebProjectionSummary),
    Codex(CodexProjectionSummary),
    Copilot(CopilotProjectionSummary),
    Gemini(GeminiProjectionSummary),
}
pub struct ImportReceipt {
    pub summary: ImportSummary,
    pub commit: Option<CollectionCommit>,
}
impl ImportReceipt {
    pub fn write(&self, out: &mut Out<'_>) -> Result<()> {
        self.summary.write(self.commit.is_some(), out)
    }
}
impl ImportSummary {
    pub fn write(&self, published: bool, out: &mut Out<'_>) -> Result<()> {
        match self {
            Self::Agy(s) => print_agy_import_summary(s, published, out),
            Self::ChatGpt(s) => print_chatgpt_import_summary(s, published, out),
            Self::ClaudeCode(s) => print_claude_code_import_summary(s, published, out),
            Self::ClaudeWeb(s) => print_claude_web_import_summary(s, published, out),
            Self::Codex(s) => print_codex_import_summary(s, published, out),
            Self::Copilot(s) => print_copilot_import_summary(s, published, out),
            Self::Gemini(s) => print_gemini_import_summary(s, published, out),
        }
    }
}
impl Archive {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self { pile, key }
    }
    fn storage(&self) -> ArchiveStorage<'_> {
        ArchiveStorage {
            pile: &self.pile,
            key: self.key.as_deref(),
        }
    }
    /// Publish one resident source atomically after complete successful scanning.
    /// Attachments are resident export filenames for ChatGPT and exact pointer
    /// keys for Gemini; other formats consume embedded assets and reject a map.
    pub fn import(
        &self,
        source: ImportSource,
        source_name: &str,
        bytes: Bytes,
        attachments: &BTreeMap<String, Bytes>,
    ) -> Result<ImportReceipt> {
        if source_name.trim().is_empty() || source_name.contains('\0') {
            bail!("resident Archive source name must be nonempty and contain no NUL");
        }
        if !attachments.is_empty()
            && !matches!(source, ImportSource::ChatGpt | ImportSource::Gemini)
        {
            bail!("this Archive format accepts embedded assets, not an external attachment map");
        }
        let mut writer =
            pollster::block_on(ArchiveImportWriter::open(&self.pile, self.key.as_deref()))?;
        let projection = match source {
            ImportSource::Agy => archive_agy::project_bytes(source_name, bytes, |p| {
                writer.stage_fragment(p.fragment)
            })
            .map(ImportSummary::Agy),
            ImportSource::ChatGpt => {
                archive_chatgpt::project_bytes(source_name, bytes, attachments, |p| {
                    writer.stage_fragment(p.fragment)
                })
                .map(ImportSummary::ChatGpt)
            }
            ImportSource::ClaudeCode => {
                archive_claude_code::project_bytes(source_name, bytes, |p| {
                    writer.stage_fragment(p.fragment)
                })
                .map(ImportSummary::ClaudeCode)
            }
            ImportSource::ClaudeWeb => archive_claude_web::project_bytes(source_name, bytes, |p| {
                writer.stage_fragment(p.fragment)
            })
            .map(ImportSummary::ClaudeWeb),
            ImportSource::Codex => archive_codex::project_bytes(source_name, bytes, |p| {
                writer.stage_fragment(p.fragment)
            })
            .map(ImportSummary::Codex),
            ImportSource::Copilot => archive_copilot::project_bytes(source_name, bytes, |p| {
                writer.stage_fragment(p.fragment)
            })
            .map(ImportSummary::Copilot),
            ImportSource::Gemini => {
                archive_gemini::project_bytes(source_name, bytes, attachments, |p| {
                    writer.stage_fragment(p.fragment)
                })
                .map(ImportSummary::Gemini)
            }
        };
        let (summary, commit) = writer.finish(projection)?;
        Ok(ImportReceipt { summary, commit })
    }
    pub fn list(&self, limit: usize, out: &mut Out<'_>) -> Result<()> {
        run_list(self.storage(), limit, out)
    }
    pub fn show(&self, prefix: &str, out: &mut Out<'_>) -> Result<()> {
        run_show(self.storage(), prefix, out)
    }
    pub fn thread(&self, prefix: &str, limit: usize, out: &mut Out<'_>) -> Result<()> {
        run_thread(self.storage(), prefix, limit, out)
    }
    pub fn search(&self, text: &str, limit: usize, out: &mut Out<'_>) -> Result<()> {
        run_search(self.storage(), text, limit, out)
    }
    pub fn index(&self, out: &mut Out<'_>) -> Result<()> {
        run_index(self.storage(), out)
    }
    pub fn replay_start(&self, persona: &str, from: Epoch) -> Result<()> {
        validate_persona(persona)?;
        let storage = self.storage();
        let facts = storage.load_comb()?;
        let position = from - hifitime::Duration::from_total_nanoseconds(1);
        if let Some(fragment) =
            plan_cursor_update(&facts, REPLAY_STREAM, persona, Some(position), None)?
        {
            publish_cursor_update(storage, fragment)?;
        }
        Ok(())
    }
    pub fn replay_stop(&self, persona: &str) -> Result<()> {
        validate_persona(persona)?;
        let storage = self.storage();
        let facts = storage.load_comb()?;
        if let Some(fragment) = plan_cursor_update(&facts, REPLAY_STREAM, persona, None, None)? {
            publish_cursor_update(storage, fragment)?;
        }
        Ok(())
    }
    pub fn replay(
        &self,
        persona: &str,
        limit: usize,
        with_tools: bool,
        out: &mut Out<'_>,
    ) -> Result<()> {
        run_replay(self.storage(), limit, with_tools, persona, out)
    }
}
fn validate_persona(persona: &str) -> Result<()> {
    if persona.trim().is_empty() {
        bail!("archive replay requires a nonempty explicit persona");
    }
    Ok(())
}

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::archive_agy::{self, ProjectionSummary as AgyProjectionSummary};
use crate::archive_chatgpt::{self, ProjectionSummary as ChatGptProjectionSummary};
use crate::archive_claude_code::{self, ProjectionSummary as ClaudeCodeProjectionSummary};
use crate::archive_claude_web::{self, ProjectionSummary as ClaudeWebProjectionSummary};
use crate::archive_codex::{self, ProjectionSummary as CodexProjectionSummary};
use crate::archive_collection::{
    self as archive_collection, ArchiveImportWriter, ArchiveTimelineBlock, ArchiveTimelineCursor,
};
use crate::archive_copilot::{self, ProjectionSummary as CopilotProjectionSummary};
use crate::archive_gemini::{self, ProjectionSummary as GeminiProjectionSummary};
use crate::collection_names::open_configured;
use crate::comb::{self as comb_model, CursorDraft, CursorResolution, CursorState};
use crate::schemas::blockdag as archive_schema;
use crate::schemas::memory::DEFAULT_COMB_SCOPE_ID;
use crate::storage::{load_signer, open_pile_strict, FactArchive};
use anyhow::{anyhow, bail, Context, Result};
use hifitime::Epoch;
use triblespace::core::collection::{
    CollectionSnapshot, CollectionSnapshotExt, CollectionStoreExt,
};
use triblespace::core::id::Id;
use triblespace::core::inline::{Inline, TryFromInline, TryToInline};
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::{BlobStoreGet, SnapshotSource};
use triblespace::core::trible::Fragment;

use anybytes::View;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::metadata;
use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::{exists, find, pattern};
use triblespace_search::tokens::hash_tokens;

type FactSnapshot = CollectionSnapshot<PileSnapshot, Rank9AcceleratedSuccinctArchiveBlob>;
type TextHandle = Inline<Handle<UTF8String>>;
type RawHandle = Inline<Handle<RawBytes>>;

use crate::out::Out;
use anybytes::Bytes;
use triblespace::core::collection::CollectionCommit;
#[derive(Clone, Copy)]
struct ArchiveStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

struct ReplayView {
    archive: FactSnapshot,
    comb_facts: FactArchive,
}

impl ArchiveStorage<'_> {
    fn load(&self) -> Result<FactSnapshot> {
        pollster::block_on(archive_collection::ensure_local(self.pile, self.key))
    }

    fn load_comb(&self) -> Result<FactArchive> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = pollster::block_on(async {
            let source = open_configured(&mut pile, DEFAULT_COMB_SCOPE_ID, signer.verifying_key())?;
            let policy = source
                .policy(&pile.snapshot().context("freeze Comb descriptor snapshot")?)
                .context("read Comb collection policy")?;
            let succinct = pile
                .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
                .context("register Succinct Comb cursor collection")?;
            let rank9 = pile
                .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
                .context("register Rank9 Comb cursor collection")?;
            drop(
                pile.ensure(source)
                    .await
                    .context("ensure Comb source dependencies")?,
            );
            drop(
                pile.maintain(succinct)
                    .await
                    .context("maintain Succinct Comb cursor collection")?,
            );
            let after = pile
                .maintain(rank9)
                .await
                .context("maintain Rank9 Comb cursor collection")?;
            after
                .collection(rank9)
                .context("attach Comb cursor collection")?
                .view::<FactArchive>()
                .context("read Comb cursor collection")
        });
        finish_pile(pile, result)
    }

    /// Attach Archive and its separate Comb cursor collection at one watermark.
    ///
    /// Both maintained views are observed through Archive's final immutable
    /// store snapshot. Later payload reads keep that same boundary.
    fn load_replay(&self) -> Result<ReplayView> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = pollster::block_on(async {
            let archive_source = open_configured(
                &mut pile,
                archive_schema::DEFAULT_SCOPE_ID,
                signer.verifying_key(),
            )?;
            let archive_policy = archive_source
                .policy(
                    &pile
                        .snapshot()
                        .context("freeze Archive descriptor snapshot")?,
                )
                .context("read Archive collection policy")?;
            let archive_succinct = pile
                .derive::<SuccinctArchiveBlob>(archive_source, (), archive_policy.clone())
                .context("register Succinct Archive fact collection")?;
            let archive_rank9 = pile
                .derive::<Rank9AcceleratedSuccinctArchiveBlob>(archive_succinct, (), archive_policy)
                .context("register Rank9 Archive fact collection")?;
            let comb_source =
                open_configured(&mut pile, DEFAULT_COMB_SCOPE_ID, signer.verifying_key())?;
            let comb_policy = comb_source
                .policy(&pile.snapshot().context("freeze Comb descriptor snapshot")?)
                .context("read Comb collection policy")?;
            let comb_succinct = pile
                .derive::<SuccinctArchiveBlob>(comb_source, (), comb_policy.clone())
                .context("register Succinct Comb cursor collection")?;
            let comb_rank9 = pile
                .derive::<Rank9AcceleratedSuccinctArchiveBlob>(comb_succinct, (), comb_policy)
                .context("register Rank9 Comb cursor collection")?;

            // Acquire the roots, maintain each immediate derivation, then
            // observe both representations through one final snapshot.
            drop(
                pile.ensure(archive_source)
                    .await
                    .context("ensure Archive source dependencies")?,
            );
            drop(
                pile.ensure(comb_source)
                    .await
                    .context("ensure Comb cursor dependencies")?,
            );
            drop(
                pile.maintain(comb_succinct)
                    .await
                    .context("maintain Succinct Comb cursor collection")?,
            );
            drop(
                pile.maintain(comb_rank9)
                    .await
                    .context("maintain Rank9 Comb cursor collection")?,
            );
            drop(
                pile.maintain(archive_succinct)
                    .await
                    .context("maintain Succinct Archive replay facts")?,
            );
            let after = pile
                .maintain(archive_rank9)
                .await
                .context("maintain Rank9 Archive replay facts")?;
            let archive = after
                .collection(archive_rank9)
                .context("attach Archive replay facts")?;
            let comb_facts = after
                .collection(comb_rank9)
                .context("attach Comb cursor collection")?
                .view::<FactArchive>()
                .context("read Comb cursor collection")?;
            Ok(ReplayView {
                archive,
                comb_facts,
            })
        });
        finish_pile(pile, result)
    }
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close();
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(close_error)) => Err(anyhow!("close Archive pile: {close_error}")),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Archive pile after failure also failed: {close_error}"
        ))),
    }
}

fn print_agy_import_summary(
    summary: &AgyProjectionSummary,
    published: bool,
    out: &mut Out<'_>,
) -> Result<()> {
    out.line(format!(
        "projected {} Antigravity transcript file(s), emitted {} fragment(s), {} source projection(s), {} content part(s)",
        summary.files_scanned,
        summary.fragments_emitted,
        summary.stats.projections_emitted,
        summary.stats.content_parts,
    ))?;
    out.line(format!(
        "records={} transparent={} raw_only={} missing_predecessors={}",
        summary.stats.records_seen,
        summary.stats.transparent_records,
        summary.stats.raw_only_records,
        summary.stats.missing_predecessors,
    ))?;
    print_collection_publication(published, out)?;
    Ok(())
}

fn print_chatgpt_import_summary(
    summary: &ChatGptProjectionSummary,
    published: bool,
    out: &mut Out<'_>,
) -> Result<()> {
    out.line(format!(
        "projected {} ChatGPT shard(s), {} conversation(s), {} mapping node(s), {} source projection(s), {} content part(s)",
        summary.files_scanned,
        summary.conversations_seen,
        summary.mapping_nodes_seen,
        summary.stats.projections_emitted,
        summary.stats.content_parts,
    ))?;
    out.line(format!(
        "attachments={} resolved={} transparent={} raw_only={} missing_predecessors={}",
        summary.attachments_seen,
        summary.attachments_resolved,
        summary.stats.transparent_records,
        summary.stats.raw_only_records,
        summary.stats.missing_predecessors,
    ))?;
    print_collection_publication(published, out)?;
    Ok(())
}

fn print_claude_code_import_summary(
    summary: &ClaudeCodeProjectionSummary,
    published: bool,
    out: &mut Out<'_>,
) -> Result<()> {
    out.line(format!(
        "projected {} Claude Code file(s), emitted {} fragment(s), {} source projection(s), {} content part(s)",
        summary.files_scanned,
        summary.fragments_emitted,
        summary.stats.source_projections,
        summary.stats.content_parts,
    ))?;
    out.line(format!(
        "skipped={} missing_identity={} skipped_parents={} unresolved_parents={} unresolved_tool_results={} undecodable_images={}",
        summary.stats.skipped_records,
        summary.stats.missing_source_identity,
        summary.stats.skipped_parents,
        summary.stats.unresolved_parents,
        summary.stats.unresolved_tool_results,
        summary.stats.undecodable_images,
    ))?;
    print_collection_publication(published, out)?;
    Ok(())
}

fn print_codex_import_summary(
    summary: &CodexProjectionSummary,
    published: bool,
    out: &mut Out<'_>,
) -> Result<()> {
    out.line(format!(
        "projected {} Codex rollout file(s), emitted {} fragment(s), {} source projection(s), {} content part(s)",
        summary.files_scanned,
        summary.fragments_emitted,
        summary.stats.source_projections,
        summary.stats.content_parts,
    ))?;
    out.line(format!(
        "records={} skipped={} invalid_timestamps={} undecodable_assets={} frozen_bytes={} trailing_bytes_ignored={}",
        summary.stats.records_seen,
        summary.stats.skipped_records,
        summary.stats.invalid_timestamps,
        summary.stats.undecodable_assets,
        summary.frozen_bytes,
        summary.trailing_bytes_ignored,
    ))?;
    print_collection_publication(published, out)?;
    Ok(())
}

fn print_claude_web_import_summary(
    summary: &ClaudeWebProjectionSummary,
    published: bool,
    out: &mut Out<'_>,
) -> Result<()> {
    out.line(format!(
        "projected {} Claude Web export file(s), emitted {} fragment(s), {} conversation(s), {} message(s), {} content part(s)",
        summary.files_scanned,
        summary.fragments_emitted,
        summary.stats.conversations,
        summary.stats.messages,
        summary.stats.common.content_parts,
    ))?;
    out.line(format!(
        "attachments={} extracted_contents={} missing_conversation_ids={} missing_message_ids={} invalid_timestamps={} missing_predecessors={}",
        summary.stats.attachments,
        summary.stats.extracted_contents,
        summary.stats.missing_conversation_uuids,
        summary.stats.missing_message_uuids,
        summary.stats.invalid_timestamps,
        summary.stats.common.missing_predecessors,
    ))?;
    print_collection_publication(published, out)?;
    Ok(())
}

fn print_copilot_import_summary(
    summary: &CopilotProjectionSummary,
    published: bool,
    out: &mut Out<'_>,
) -> Result<()> {
    out.line(format!(
        "projected {} Copilot session file(s), ignored {} unrelated JSON file(s), emitted {} fragment(s), {} source projection(s), {} content part(s)",
        summary.files_scanned,
        summary.files_ignored,
        summary.fragments_emitted,
        summary.stats.projections_emitted,
        summary.stats.content_parts,
    ))?;
    out.line(format!(
        "records={} transparent={} raw_only={} missing_predecessors={}",
        summary.stats.records_seen,
        summary.stats.transparent_records,
        summary.stats.raw_only_records,
        summary.stats.missing_predecessors,
    ))?;
    print_collection_publication(published, out)?;
    Ok(())
}

fn print_gemini_import_summary(
    summary: &GeminiProjectionSummary,
    published: bool,
    out: &mut Out<'_>,
) -> Result<()> {
    out.line(format!(
        "projected {} Gemini Takeout file(s), ignored {} unrelated HTML file(s), {} activity card(s), {} source projection(s), {} content part(s)",
        summary.files_scanned,
        summary.files_ignored,
        summary.cards_seen,
        summary.stats.projections_emitted,
        summary.stats.content_parts,
    ))?;
    out.line(format!(
        "assets={} resolved={} transparent={} raw_only={} missing_predecessors={}",
        summary.assets_seen,
        summary.assets_resolved,
        summary.stats.transparent_records,
        summary.stats.raw_only_records,
        summary.stats.missing_predecessors,
    ))?;
    print_collection_publication(published, out)?;
    Ok(())
}

fn print_collection_publication(published: bool, out: &mut Out<'_>) -> Result<()> {
    out.line(format!(
        "Archive collection: {}",
        if published {
            "one signed COMMIT published"
        } else {
            "unchanged (no novel facts)"
        }
    ))?;
    Ok(())
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

fn format_interval(interval: Option<(i128, i128)>) -> String {
    let Some((lower, upper)) = interval else {
        return "<untimed>".to_owned();
    };
    let lower = Epoch::from_tai_duration(hifitime::Duration::from_total_nanoseconds(lower));
    let upper = Epoch::from_tai_duration(hifitime::Duration::from_total_nanoseconds(upper));
    if lower == upper {
        lower.to_string()
    } else {
        format!("{lower}..{upper}")
    }
}

fn read_text(reader: &PileSnapshot, handle: TextHandle) -> Result<String> {
    let value: View<str> = reader.get(handle).context("read Archive text")?;
    Ok(value.to_string())
}

fn entity_label(
    facts: &FactArchive,
    reader: &PileSnapshot,
    id: Id,
    namespace: &str,
) -> Result<String> {
    let names: BTreeSet<_> = find!(
        value: TextHandle,
        pattern!(facts, [{ id @ metadata::name: ?value }])
    )
    .map(|handle| read_text(reader, handle))
    .collect::<Result<_>>()?;
    if names.is_empty() {
        Ok(format!("{namespace}:{id:X}"))
    } else {
        Ok(names.into_iter().collect::<Vec<_>>().join(" / "))
    }
}

fn projection_actor(facts: &FactArchive, reader: &PileSnapshot, projection: Id) -> Result<String> {
    let mut values = Vec::new();
    for attribute in [
        &*archive_schema::source_projection::raw_author,
        &*archive_schema::source_projection::raw_role,
        &*archive_schema::source_projection::raw_model,
    ] {
        let handles: BTreeSet<_> = find!(
            value: TextHandle,
            pattern!(facts, [{ projection @ attribute: ?value }])
        )
        .collect();
        for handle in handles {
            values.push(read_text(reader, handle)?);
        }
    }
    Ok(if values.is_empty() {
        "<unattributed>".to_owned()
    } else {
        values.join("/")
    })
}

fn block_snippet(facts: &FactArchive, reader: &PileSnapshot, block: Id) -> Result<String> {
    let parts: BTreeSet<_> = find!(
        (ordinal: u64, part: Id, fact: Id),
        pattern!(facts, [
            { block @ archive_schema::block::contains: ?part },
            { ?part @ archive_schema::content_part::ordinal: ?ordinal,
                archive_schema::content_part::fact: ?fact },
        ])
    )
    .collect();
    let mut values = Vec::new();
    for (_, _, fact) in parts {
        for text in find!(
            text: TextHandle,
            pattern!(facts, [{ fact @ archive_schema::content_fact::payload: ?text }])
        ) {
            values.push(read_text(reader, text)?);
        }
        for blob in find!(
            blob: RawHandle,
            pattern!(facts, [{ fact @ archive_schema::content_fact::blob: ?blob }])
        ) {
            values.push(format!("[resident {}]", hex::encode_upper(blob.raw)));
        }
        for pointer in find!(
            pointer: TextHandle,
            pattern!(facts, [{ fact @ archive_schema::content_fact::asset_pointer: ?pointer }])
        ) {
            values.push(format!("[external {}]", read_text(reader, pointer)?));
        }
    }
    Ok(snippet(&values.join(" "), 120))
}

fn render_projection_summary(
    facts: &FactArchive,
    reader: &PileSnapshot,
    projection: Id,
) -> Result<String> {
    let timestamp = find!(
        value: (i128, i128),
        pattern!(facts, [{
            projection @ archive_schema::source_projection::source_timestamp: ?value
        }])
    )
    .min()
    .or_else(|| {
        find!(
            value: (i128, i128),
            pattern!(facts, [
                { projection @ archive_schema::source_projection::projects_to: _?block },
                { _?block @ archive_schema::block::timestamp: ?value },
            ])
        )
        .min()
    });
    let blocks: BTreeSet<_> = find!(
        block: Id,
        pattern!(facts, [{
            projection @ archive_schema::source_projection::projects_to: ?block
        }])
    )
    .collect();
    let snippets = blocks
        .into_iter()
        .map(|block| block_snippet(facts, reader, block))
        .collect::<Result<Vec<_>>>()?;
    Ok(format!(
        "{} {} {} {}",
        short_id(projection),
        format_interval(timestamp),
        projection_actor(facts, reader, projection)?,
        snippets.join(" / "),
    ))
}

fn render_parts(
    out: &mut String,
    facts: &FactArchive,
    reader: &PileSnapshot,
    block: Id,
    include_all: bool,
) -> Result<()> {
    let parts: BTreeSet<_> = find!(
        (ordinal: u64, part: Id, fact: Id, modality: Id, direction: Id),
        pattern!(facts, [
            { block @ archive_schema::block::contains: ?part },
            { ?part @ archive_schema::content_part::ordinal: ?ordinal,
                archive_schema::content_part::fact: ?fact },
            { ?fact @ archive_schema::content_fact::modality: ?modality,
                archive_schema::content_fact::direction: ?direction },
        ])
    )
    .collect();
    for (ordinal, part, fact, modality, direction) in parts {
        if !include_all && modality != archive_schema::content_fact::modality::TEXT {
            continue;
        }
        writeln!(
            out,
            "part[{ordinal}]: {} {} id={part:X} fact={fact:X}",
            entity_label(facts, reader, modality, "modality")?,
            entity_label(facts, reader, direction, "direction")?,
        )?;
        for target in find!(
            target: Id,
            pattern!(facts, [{ part @ archive_schema::content_part::responds_to: ?target }])
        ) {
            writeln!(out, "  responds_to: {target:X}")?;
        }
        for text in find!(
            text: TextHandle,
            pattern!(facts, [{ fact @ archive_schema::content_fact::payload: ?text }])
        ) {
            writeln!(out, "  text:")?;
            for line in read_text(reader, text)?.lines() {
                writeln!(out, "    {line}")?;
            }
        }
        for blob in find!(
            blob: RawHandle,
            pattern!(facts, [{ fact @ archive_schema::content_fact::blob: ?blob }])
        ) {
            writeln!(out, "  resident_blob: {}", hex::encode_upper(blob.raw))?;
        }
        for pointer in find!(
            pointer: TextHandle,
            pattern!(facts, [{ fact @ archive_schema::content_fact::asset_pointer: ?pointer }])
        ) {
            writeln!(out, "  external_pointer: {}", read_text(reader, pointer)?)?;
        }
        for (label, attribute) in [
            ("media_type", &*archive_schema::content_fact::media_type),
            (
                "asset_namespace",
                &*archive_schema::content_fact::asset_namespace,
            ),
        ] {
            for value in find!(value: Id, pattern!(facts, [{ fact @ attribute: ?value }])) {
                writeln!(out, "  {label}: {value:X}")?;
            }
        }
        for size in find!(
            size: u128,
            pattern!(facts, [{ fact @ archive_schema::content_fact::asset_size: ?size }])
        ) {
            writeln!(out, "  size: {size}")?;
        }
        for resolution in find!(
            resolution: RawHandle,
            pattern!(facts, [{ fact @ archive_schema::content_fact::resolved_to: ?resolution }])
        ) {
            writeln!(out, "  resolution: {}", hex::encode_upper(resolution.raw))?;
        }
        for resolution in find!(
            resolution: RawHandle,
            pattern!(facts, [{ part @ archive_schema::content_part::resolution: ?resolution }])
        ) {
            writeln!(
                out,
                "  selected_resolution: {}",
                hex::encode_upper(resolution.raw)
            )?;
        }
    }
    Ok(())
}

fn render_projection(facts: &FactArchive, reader: &PileSnapshot, projection: Id) -> Result<String> {
    let mut out = String::new();
    writeln!(out, "projection: {projection:X}")?;
    for (label, attribute) in [
        (
            "source_namespace",
            &*archive_schema::source_projection::source_namespace,
        ),
        (
            "semantic_predecessor_support",
            &*archive_schema::source_projection::semantic_predecessor_support,
        ),
        ("author", &*archive_schema::source_projection::author),
        (
            "experiencer",
            &*archive_schema::source_projection::experiencer,
        ),
    ] {
        for value in find!(value: Id, pattern!(facts, [{ projection @ attribute: ?value }])) {
            writeln!(out, "{label}: {value:X}")?;
        }
    }
    for (label, attribute) in [
        (
            "source_locator",
            &*archive_schema::source_projection::source_locator,
        ),
        (
            "raw_author",
            &*archive_schema::source_projection::raw_author,
        ),
        ("raw_role", &*archive_schema::source_projection::raw_role),
        ("raw_model", &*archive_schema::source_projection::raw_model),
        ("source_path", &*crate::schemas::files::file::source_path),
    ] {
        for value in find!(
            value: TextHandle,
            pattern!(facts, [{ projection @ attribute: ?value }])
        ) {
            writeln!(out, "{label}: {}", read_text(reader, value)?)?;
        }
    }
    for raw in find!(
        raw: RawHandle,
        pattern!(facts, [{ projection @ archive_schema::source_projection::raw_record: ?raw }])
    ) {
        writeln!(out, "raw_record: {}", hex::encode_upper(raw.raw))?;
    }
    for timestamp in find!(
        timestamp: (i128, i128),
        pattern!(facts, [{
            projection @ archive_schema::source_projection::source_timestamp: ?timestamp
        }])
    ) {
        writeln!(
            out,
            "source_timestamp: {}",
            format_interval(Some(timestamp))
        )?;
    }
    let blocks: BTreeSet<_> = find!(
        block: Id,
        pattern!(facts, [{ projection @ archive_schema::source_projection::projects_to: ?block }])
    )
    .collect();
    for block in blocks {
        writeln!(out, "block: {block:X}")?;
        for timestamp in find!(
            timestamp: (i128, i128),
            pattern!(facts, [{ block @ archive_schema::block::timestamp: ?timestamp }])
        ) {
            writeln!(out, "block_timestamp: {}", format_interval(Some(timestamp)))?;
        }
        for previous in find!(
            previous: Id,
            pattern!(facts, [{ block @ archive_schema::block::previous: ?previous }])
        ) {
            writeln!(out, "block_previous: {previous:X}")?;
        }
        render_parts(&mut out, facts, reader, block, true)?;
    }
    Ok(out)
}

fn resolve_prefix(ids: impl IntoIterator<Item = Id>, prefix: &str) -> Result<Id> {
    let prefix = prefix.trim();
    if prefix.is_empty() || prefix.len() > 32 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("Archive projection prefix must contain 1..=32 hexadecimal digits");
    }
    let prefix = prefix.to_ascii_uppercase();
    let matches: BTreeSet<_> = ids
        .into_iter()
        .filter(|id| format!("{id:X}").starts_with(&prefix))
        .collect();
    match matches.len() {
        0 => bail!("no Archive source projection matches {prefix}"),
        1 => Ok(*matches.first().expect("one prefix match")),
        _ => bail!("Archive projection prefix {prefix} is ambiguous"),
    }
}

fn run_list(storage: ArchiveStorage<'_>, limit: usize, out: &mut Out<'_>) -> Result<()> {
    let observed = storage.load()?;
    let facts = observed.view::<FactArchive>()?;
    let mut rows = Vec::new();
    for projection in find!(
        projection: Id,
        pattern!(&facts, [{
            ?projection @ metadata::tag: &archive_schema::source_projection::KIND
        }])
    ) {
        let timestamp = find!(
            timestamp: (i128, i128),
            pattern!(&facts, [{
                projection @ archive_schema::source_projection::source_timestamp: ?timestamp
            }])
        )
        .map(|(lower, _)| lower)
        .min()
        .or_else(|| {
            find!(
                timestamp: (i128, i128),
                pattern!(&facts, [
                    { projection @ archive_schema::source_projection::projects_to: _?block },
                    { _?block @ archive_schema::block::timestamp: ?timestamp },
                ])
            )
            .map(|(lower, _)| lower)
            .min()
        });
        rows.push((timestamp, projection));
    }
    rows.sort_unstable_by(|left, right| right.cmp(left));
    for (_, projection) in rows.into_iter().take(limit) {
        out.line(format!(
            "{}",
            render_projection_summary(&facts, observed.snapshot(), projection)?
        ))?;
    }
    Ok(())
}

fn run_show(storage: ArchiveStorage<'_>, prefix: &str, out: &mut Out<'_>) -> Result<()> {
    let observed = storage.load()?;
    let facts = observed.view::<FactArchive>()?;
    let id = resolve_prefix(
        find!(
            projection: Id,
            pattern!(&facts, [{
                ?projection @ metadata::tag: &archive_schema::source_projection::KIND
            }])
        ),
        prefix,
    )?;
    out.text(format!(
        "{}",
        render_projection(&facts, observed.snapshot(), id)?
    ))?;
    Ok(())
}

fn load_thread(facts: &FactArchive, projection_prefix: &str, limit: usize) -> Result<Vec<Id>> {
    if limit == 0 {
        bail!("thread limit must be at least 1");
    }
    let leaf = resolve_prefix(
        find!(
            projection: Id,
            pattern!(facts, [{
                ?projection @ metadata::tag: &archive_schema::source_projection::KIND
            }])
        ),
        projection_prefix,
    )?;
    let mut pending: BTreeSet<_> = find!(
        block: Id,
        pattern!(facts, [{ leaf @ archive_schema::source_projection::projects_to: ?block }])
    )
    .collect();
    let mut parents = BTreeMap::<Id, BTreeSet<Id>>::new();
    while let Some(block) = pending.pop_first() {
        if parents.contains_key(&block) {
            continue;
        }
        if parents.len() == limit {
            bail!("thread ancestry exceeds {limit} canonical blocks; increase --limit so no fork is hidden");
        }
        let previous: BTreeSet<_> = find!(
            previous: Id,
            pattern!(facts, [{ block @ archive_schema::block::previous: ?previous }])
        )
        .collect();
        pending.extend(previous.iter().copied());
        parents.insert(block, previous);
    }
    let mut indegree: BTreeMap<Id, usize> = parents
        .iter()
        .map(|(block, previous)| (*block, previous.len()))
        .collect();
    let mut children = BTreeMap::<Id, BTreeSet<Id>>::new();
    for (block, previous) in &parents {
        for parent in previous {
            children.entry(*parent).or_default().insert(*block);
        }
    }
    let mut ready: BTreeSet<Id> = indegree
        .iter()
        .filter_map(|(block, count)| (*count == 0).then_some(*block))
        .collect();
    let mut ordered = Vec::with_capacity(parents.len());
    while let Some(block) = ready.pop_first() {
        ordered.push(block);
        for child in children.get(&block).into_iter().flatten() {
            let count = indegree
                .get_mut(child)
                .expect("every child has an indegree");
            *count -= 1;
            if *count == 0 {
                ready.insert(*child);
            }
        }
    }
    if ordered.len() != parents.len() {
        bail!("Archive thread contains a block cycle");
    }
    Ok(ordered)
}

fn render_block(
    facts: &FactArchive,
    reader: &PileSnapshot,
    block: Id,
    include_all_parts: bool,
) -> Result<String> {
    let mut out = String::new();
    writeln!(out, "block: {block:X}")?;
    let timestamp = find!(
        value: (i128, i128),
        pattern!(facts, [{ block @ archive_schema::block::timestamp: ?value }])
    )
    .min()
    .or_else(|| {
        find!(
            value: (i128, i128),
            pattern!(facts, [{
                _?receipt @ archive_schema::source_projection::projects_to: block,
                archive_schema::source_projection::source_timestamp: ?value
            }])
        )
        .min()
    });
    writeln!(out, "timestamp: {}", format_interval(timestamp))?;
    for previous in find!(
        previous: Id,
        pattern!(facts, [{ block @ archive_schema::block::previous: ?previous }])
    ) {
        writeln!(out, "previous: {previous:X}")?;
    }
    let receipts: BTreeSet<_> = find!(
        (receipt: Id, locator: TextHandle),
        pattern!(facts, [{
            ?receipt @ archive_schema::source_projection::projects_to: block,
            archive_schema::source_projection::source_locator: ?locator
        }])
    )
    .collect();
    for (receipt, locator) in receipts {
        writeln!(
            out,
            "receipt: {receipt:X} {} {}",
            read_text(reader, locator)?,
            projection_actor(facts, reader, receipt)?,
        )?;
    }
    render_parts(&mut out, facts, reader, block, include_all_parts)?;
    Ok(out)
}

fn run_thread(
    storage: ArchiveStorage<'_>,
    prefix: &str,
    limit: usize,
    out: &mut Out<'_>,
) -> Result<()> {
    let observed = storage.load()?;
    let facts = observed.view::<FactArchive>()?;
    for (index, block) in load_thread(&facts, prefix, limit)?.into_iter().enumerate() {
        if index != 0 {
            out.line(format!("---"))?;
        }
        out.text(format!(
            "{}",
            render_block(&facts, observed.snapshot(), block, true)?
        ))?;
    }
    Ok(())
}

fn run_search(
    storage: ArchiveStorage<'_>,
    text: &str,
    limit: usize,
    out: &mut Out<'_>,
) -> Result<()> {
    let (observed, index) = pollster::block_on(archive_collection::ensure_search_local(
        storage.pile,
        storage.key,
    ))?;
    let facts = observed.view::<FactArchive>()?;
    for (document, score) in index
        .query_multi(&hash_tokens(&text))
        .into_iter()
        .take(limit)
    {
        let block = Id::try_from_inline(&document)
            .map_err(|error| anyhow!("Archive BM25 document is not a block id: {error:?}"))?;
        let receipts: BTreeSet<_> = find!(
            receipt: Id,
            pattern!(&facts, [{
                ?receipt @ archive_schema::source_projection::projects_to: block
            }])
        )
        .collect();
        out.line(format!(
            "{score:.4} {} {} receipt(s) {}",
            short_id(block),
            receipts.len(),
            block_snippet(&facts, observed.snapshot(), block)?,
        ))?;
    }
    Ok(())
}

fn run_index(storage: ArchiveStorage<'_>, out: &mut Out<'_>) -> Result<()> {
    let (succinct, bm25) = pollster::block_on(async {
        let succinct = archive_collection::ensure_succinct_index(storage.pile, storage.key).await?;
        let bm25 = archive_collection::ensure_bm25_index(storage.pile, storage.key).await?;
        Ok::<_, anyhow::Error>((succinct, bm25))
    })?;
    out.line(format!(
        "Archive: {} distinct source element(s) covered by accelerated-Succinct",
        succinct.source_elements,
    ))?;
    out.line(format!(
        "Archive BM25: {} distinct source element(s), {} resident cover segment(s)",
        bm25.source_elements, bm25.cover_segments,
    ))?;
    Ok(())
}

pub fn parse_tai_timestamp(value: &str) -> Result<Epoch> {
    let (date, time) = value
        .split_once('T')
        .ok_or_else(|| anyhow!("invalid timestamp (expected YYYY-MM-DDTHH:MM:SS): {value}"))?;
    let date = date.split('-').collect::<Vec<_>>();
    let time = time.split(':').collect::<Vec<_>>();
    if date.len() != 3 || time.len() != 3 {
        bail!("invalid timestamp (expected YYYY-MM-DDTHH:MM:SS): {value}");
    }
    Epoch::maybe_from_gregorian_tai(
        date[0].parse().context("year")?,
        date[1].parse().context("month")?,
        date[2].parse().context("day")?,
        time[0].parse().context("hour")?,
        time[1].parse().context("minute")?,
        time[2].parse().context("second")?,
        0,
    )
    .context("invalid Gregorian TAI timestamp")
}

fn cursor_state(position: Option<Epoch>, anchor: Option<Id>) -> CursorState {
    CursorState {
        position: position.map(|epoch| (epoch, epoch).try_to_inline().unwrap()),
        anchor,
        grain: None,
    }
}

fn plan_cursor_update(
    facts: &FactArchive,
    stream: &str,
    persona: &str,
    position: Option<Epoch>,
    anchor: Option<Id>,
) -> Result<Option<Fragment>> {
    let state = cursor_state(position, anchor);
    let predecessors = match comb_model::resolution(facts, stream, persona)? {
        None => BTreeSet::new(),
        Some(ref resolution) => {
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
        anchor: state.anchor,
        grain: state.grain,
        predecessors,
        observed_at: BTreeSet::new(),
    })?;
    Ok(Some(fragment))
}

fn active_archive_cursor(
    facts: &FactArchive,
    stream: &str,
    persona: &str,
) -> Result<ArchiveTimelineCursor> {
    let resolution = comb_model::resolution(facts, stream, persona)?.ok_or_else(|| {
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
    Ok(state.anchor.map_or(
        ArchiveTimelineCursor::AfterTime(lower),
        ArchiveTimelineCursor::AfterBlock,
    ))
}

fn publish_cursor_update(storage: ArchiveStorage<'_>, fragment: Fragment) -> Result<()> {
    let signer = load_signer(storage.pile, storage.key)?;
    let mut pile = open_pile_strict(storage.pile)?;
    let result = (|| {
        let collection = open_configured(&mut pile, DEFAULT_COMB_SCOPE_ID, signer.verifying_key())?;
        pile.commit(collection, &signer, fragment)
            .context("publish archive replay cursor")?;
        Ok(())
    })();
    finish_pile(pile, result)
}

const REPLAY_STREAM: &str = "archive-replay";

fn split_replay_batch(
    timeline: Vec<ArchiveTimelineBlock>,
    limit: usize,
) -> (Vec<ArchiveTimelineBlock>, usize) {
    let remaining = timeline.len().saturating_sub(limit);
    let selected = timeline.into_iter().take(limit).collect();
    (selected, remaining)
}

fn run_replay(
    storage: ArchiveStorage<'_>,
    limit: usize,
    with_tools: bool,
    persona: &str,
    out: &mut Out<'_>,
) -> Result<()> {
    if limit == 0 {
        bail!("replay limit must be at least 1");
    }
    validate_persona(persona)?;
    let replay = storage.load_replay()?;
    let cursor = active_archive_cursor(&replay.comb_facts, REPLAY_STREAM, persona)?;
    let facts = replay.archive.view::<FactArchive>()?;
    let timeline = archive_collection::timeline_after(&facts, cursor)?
        .into_iter()
        .filter(|item| {
            with_tools
                || exists!(pattern!(&facts, [
                    { item.block @ archive_schema::block::contains: _?part },
                    { _?part @ archive_schema::content_part::fact: _?fact },
                    { _?fact @ archive_schema::content_fact::modality:
                        &archive_schema::content_fact::modality::TEXT },
                ]))
        })
        .collect();
    let (selected, remaining) = split_replay_batch(timeline, limit);
    if selected.is_empty() {
        out.line(format!(
            "replay complete: nothing after the cursor. The past is read."
        ))?;
        return Ok(());
    }

    for block in &selected {
        out.text(format!(
            "{}",
            render_block(&facts, replay.archive.snapshot(), block.block, with_tools)?
        ))?;
        out.line(format!("---"))?;
    }
    let last = selected.last().expect("selected is nonempty");
    let last_epoch =
        Epoch::from_tai_duration(hifitime::Duration::from_total_nanoseconds(last.position));
    let fragment = plan_cursor_update(
        &replay.comb_facts,
        REPLAY_STREAM,
        persona,
        Some(last_epoch),
        Some(last.block),
    )?
    .ok_or_else(|| anyhow!("replay emitted blocks without advancing its cursor"))?;
    publish_cursor_update(storage, fragment)?;
    out.line(format!(
        "batch: {} block(s); cursor -> {}; {} remaining",
        selected.len(),
        last_epoch,
        remaining,
    ))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::cli::{Cli, CliImportSource, Command};
    use super::*;
    use crate::storage::initialize_signer;
    use clap::{CommandFactory, Parser};
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

    fn run_import(storage: ArchiveStorage<'_>, path: &Path, source: CliImportSource) -> Result<()> {
        super::super::cli::import_paths(
            storage.pile,
            storage.key,
            &[path.to_path_buf()],
            source,
            &mut Out::new(&mut |_| Ok(())),
        )
    }

    fn archive_root_count(fixture: &Fixture) -> usize {
        let observed = storage(fixture).load().unwrap();
        observed
            .support()
            .commits(observed.snapshot())
            .unwrap()
            .len()
    }

    fn projection_ids(facts: &FactArchive) -> Vec<Id> {
        find!(
            projection: Id,
            pattern!(facts, [{
                ?projection @ metadata::tag: &archive_schema::source_projection::KIND
            }])
        )
        .collect()
    }

    #[test]
    fn cli_surface_has_no_branch_or_sidecar_controls() {
        let commands: BTreeSet<_> = Cli::command()
            .get_subcommands()
            .map(|command| command.get_name().to_owned())
            .collect();
        assert_eq!(
            commands,
            ["import", "index", "list", "replay", "search", "show", "thread",]
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
        let default_source = Cli::try_parse_from([
            "archive",
            "--pile",
            "archive.pile",
            "import",
            "rollout.jsonl",
        ])
        .unwrap();
        assert!(matches!(
            default_source.command,
            Some(Command::Import {
                source: CliImportSource::ClaudeCode,
                ..
            })
        ));
        for (spelling, expected) in [
            ("agy", CliImportSource::Agy),
            ("chatgpt", CliImportSource::ChatGpt),
            ("claude-code", CliImportSource::ClaudeCode),
            ("claude-web", CliImportSource::ClaudeWeb),
            ("codex", CliImportSource::Codex),
            ("copilot", CliImportSource::Copilot),
            ("gemini", CliImportSource::Gemini),
        ] {
            let parsed = Cli::try_parse_from([
                "archive",
                "--pile",
                "archive.pile",
                "import",
                "source",
                "--source",
                spelling,
            ])
            .unwrap();
            assert!(matches!(
                parsed.command,
                Some(Command::Import { source, .. }) if source == expected
            ));
        }
    }

    #[test]
    fn new_source_importers_each_publish_one_validated_commit() {
        let fixture = fixture();

        let chatgpt = fixture._directory.path().join("conversations.json");
        fs::write(
            &chatgpt,
            r#"[{"id":"chatgpt-cli","mapping":{"node":{"id":"node","parent":null,"message":{"id":"message","author":{"role":"user"},"content":{"content_type":"text","parts":["chatgpt"]}}}}}]"#,
        )
        .unwrap();
        run_import(storage(&fixture), &chatgpt, CliImportSource::ChatGpt).unwrap();
        assert_eq!(archive_root_count(&fixture), 1);

        let claude_web = fixture._directory.path().join("claude-web.json");
        fs::write(
            &claude_web,
            r#"[{"uuid":"claude-cli","chat_messages":[{"uuid":"message","sender":"human","text":"claude"}]}]"#,
        )
        .unwrap();
        run_import(storage(&fixture), &claude_web, CliImportSource::ClaudeWeb).unwrap();
        assert_eq!(archive_root_count(&fixture), 2);

        let copilot = fixture._directory.path().join("copilot.json");
        fs::write(
            &copilot,
            r#"{"sessionId":"copilot-cli","requests":[{"requestId":"request","message":{"text":"copilot"},"response":[{"value":"answer"}]}]}"#,
        )
        .unwrap();
        run_import(storage(&fixture), &copilot, CliImportSource::Copilot).unwrap();
        assert_eq!(archive_root_count(&fixture), 3);

        let agy = fixture._directory.path().join("transcript_full.jsonl");
        fs::write(
            &agy,
            concat!(
                r#"{"source":"USER_INPUT","content":"agy","step_index":1}"#,
                "\n",
            ),
        )
        .unwrap();
        run_import(storage(&fixture), &agy, CliImportSource::Agy).unwrap();
        assert_eq!(archive_root_count(&fixture), 4);

        let gemini = fixture._directory.path().join("My Activity.html");
        fs::write(
            &gemini,
            concat!(
                "<html><body><div class=\"outer-cell mdl-cell mdl-cell--12-col mdl-shadow--2dp\"><div>",
                "<div class=\"header-cell\"><p>Gemini Apps<br></p></div>",
                "<div class=\"content-cell mdl-cell mdl-cell--6-col mdl-typography--body-1\">",
                "Prompted&nbsp;gemini<br>18 Sept 2025, 12:02:52 CET<br><p>answer</p>",
                "</div><div class=\"content-cell mdl-cell mdl-cell--6-col mdl-typography--body-1 mdl-typography--text-right\"></div>",
                "</div></div></body></html>",
            ),
        )
        .unwrap();
        run_import(storage(&fixture), &gemini, CliImportSource::Gemini).unwrap();
        assert_eq!(archive_root_count(&fixture), 5);

        assert_eq!(
            projection_ids(
                &storage(&fixture)
                    .load()
                    .unwrap()
                    .view::<FactArchive>()
                    .unwrap()
            )
            .len(),
            10
        );
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

        run_import(storage(&fixture), &source, CliImportSource::ClaudeCode).unwrap();
        assert_eq!(archive_root_count(&fixture), 1);
        let archive = storage(&fixture).load().unwrap();
        assert_eq!(
            projection_ids(&archive.view::<FactArchive>().unwrap()).len(),
            2
        );
        drop(archive);
        let after_first = fs::metadata(&fixture.pile).unwrap().len();

        run_import(storage(&fixture), &source, CliImportSource::ClaudeCode).unwrap();
        assert_eq!(archive_root_count(&fixture), 1);
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), after_first);
    }

    #[test]
    fn codex_import_uses_receipt_time_and_replays_one_semantic_block_once() {
        let fixture = fixture();
        let first = fixture._directory.path().join("first-rollout.jsonl");
        let second = fixture._directory.path().join("second-rollout.jsonl");
        fs::write(
            &first,
            concat!(
                r#"{"timestamp":"2026-08-16T08:00:00Z","type":"session_meta","payload":{"id":"first-session","session_id":"first-session"}}"#,
                "\n",
                r#"{"timestamp":"2026-08-16T08:01:00Z","type":"event_msg","payload":{"type":"user_message","message":"same semantic message"}}"#,
                "\n",
            ),
        )
        .unwrap();
        fs::write(
            &second,
            concat!(
                r#"{"timestamp":"2026-08-16T08:00:00Z","type":"session_meta","payload":{"id":"second-session","session_id":"second-session"}}"#,
                "\n",
                r#"{"timestamp":"2026-08-16T08:02:00Z","type":"event_msg","payload":{"type":"user_message","message":"same semantic message"}}"#,
                "\n",
            ),
        )
        .unwrap();

        run_import(storage(&fixture), &first, CliImportSource::Codex).unwrap();
        run_import(storage(&fixture), &second, CliImportSource::Codex).unwrap();

        let archive = storage(&fixture).load().unwrap();
        let facts = archive.view::<FactArchive>().unwrap();
        let ids = projection_ids(&facts);
        assert_eq!(ids.len(), 2);
        let blocks: BTreeSet<_> = find!(
            block: Id,
            pattern!(&facts, [{
                _?projection @ archive_schema::source_projection::projects_to: ?block
            }])
        )
        .collect();
        assert_eq!(blocks.len(), 1);
        let block = *blocks.first().unwrap();
        assert!(!exists!(pattern!(&facts, [{
            block @ archive_schema::block::timestamp: _?timestamp
        }])));
        for projection in ids {
            assert!(
                !render_projection_summary(&facts, archive.snapshot(), projection)
                    .unwrap()
                    .contains("<untimed>")
            );
        }
        let earliest_receipt_key = find!(
            timestamp: (i128, i128),
            pattern!(&facts, [{
                _?projection @ archive_schema::source_projection::source_timestamp: ?timestamp
            }])
        )
        .map(|(lower, _)| lower)
        .min()
        .unwrap();
        assert!(!render_block(&facts, archive.snapshot(), block, false)
            .unwrap()
            .contains("<untimed>"));
        let timeline =
            archive_collection::timeline_after(&facts, ArchiveTimelineCursor::AfterTime(i128::MIN))
                .unwrap();
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].position, earliest_receipt_key);
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

        let error =
            run_import(storage(&fixture), &source, CliImportSource::ClaudeCode).unwrap_err();
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
        run_import(storage(&fixture), &source, CliImportSource::ClaudeCode).unwrap();
        let first = pollster::block_on(archive_collection::ensure_succinct_index(
            &fixture.pile,
            Some(&fixture.key),
        ))
        .unwrap();

        assert_eq!(first.source_elements, 1);
        assert_ne!(first.source_collection, first.target_collection);
        let before = fs::metadata(&fixture.pile).unwrap().len();

        let archive = storage(&fixture).load().unwrap();
        let facts = archive.view::<FactArchive>().unwrap();
        let id = projection_ids(&facts)[0];
        assert!(render_projection(&facts, archive.snapshot(), id)
            .unwrap()
            .contains("quasar needle"));
        assert_eq!(
            load_thread(&facts, &format!("{id:X}"), 10).unwrap().len(),
            1
        );
        drop(archive);
        let repeated = pollster::block_on(archive_collection::ensure_succinct_index(
            &fixture.pile,
            Some(&fixture.key),
        ))
        .unwrap();
        assert_eq!(repeated, first);

        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), before);

        let first_bm25 = pollster::block_on(archive_collection::ensure_bm25_index(
            &fixture.pile,
            Some(&fixture.key),
        ))
        .unwrap();

        assert_eq!(first_bm25.source_elements, 1);
        assert_eq!(first_bm25.cover_segments, 1);
        let after_bm25 = fs::metadata(&fixture.pile).unwrap().len();
        assert_eq!(
            pollster::block_on(archive_collection::ensure_bm25_index(
                &fixture.pile,
                Some(&fixture.key),
            ))
            .unwrap(),
            first_bm25
        );
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), after_bm25);

        let search = pollster::block_on(archive_collection::ensure_search_local(
            &fixture.pile,
            Some(&fixture.key),
        ))
        .unwrap();
        let hits = search.1.query_multi(&hash_tokens("quasar"));
        assert_eq!(hits.len(), 1);
        let block = Id::try_from_inline(&hits[0].0).unwrap();
        let found: Vec<_> = find!(
            projection: Id,
            pattern!(&facts, [{
                ?projection @ archive_schema::source_projection::projects_to: block
            }])
        )
        .collect();
        assert_eq!(found, [id]);
        drop(search);
        run_search(
            storage(&fixture),
            "quasar",
            10,
            &mut Out::new(&mut |_| Ok(())),
        )
        .unwrap();
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
        run_import(storage(&fixture), &source, CliImportSource::ClaudeCode).unwrap();
        let archive = storage(&fixture).load().unwrap();
        let facts = archive.view::<FactArchive>().unwrap();
        let joined = projection_ids(&facts)
            .into_iter()
            .find(|id| {
                render_projection_summary(&facts, archive.snapshot(), *id)
                    .unwrap()
                    .contains("joined")
            })
            .unwrap();
        let thread = load_thread(&facts, &format!("{joined:X}"), 3).unwrap();
        assert_eq!(thread.len(), 3);
        let parent_count: usize = thread
            .iter()
            .map(|block| {
                find!(
                    previous: Id,
                    pattern!(&facts, [{ block @ archive_schema::block::previous: ?previous }])
                )
                .count()
            })
            .sum();
        assert_eq!(parent_count, 2);
        assert!(load_thread(&facts, &format!("{joined:X}"), 2)
            .unwrap_err()
            .to_string()
            .contains("no fork is hidden"));
    }

    #[test]
    fn replay_rejects_zero_limit_and_exact_cursor_can_split_equal_timestamps() {
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
        run_import(storage(&fixture), &source, CliImportSource::ClaudeCode).unwrap();

        let archive = storage(&fixture).load().unwrap();
        let facts = archive.view::<FactArchive>().unwrap();
        let timeline =
            archive_collection::timeline_after(&facts, ArchiveTimelineCursor::AfterTime(i128::MIN))
                .unwrap();
        assert_eq!(timeline.len(), 3);
        assert_eq!(timeline[0].position, timeline[1].position);
        let first_cursor = timeline[0].cursor();
        let (selected, remaining) = split_replay_batch(timeline, 1);
        assert_eq!(selected.len(), 1);
        assert_eq!(remaining, 2);

        let resumed = archive_collection::timeline_after(&facts, first_cursor).unwrap();
        assert_eq!(resumed.len(), 2, "the equal-time peer is not skipped");

        let error = run_replay(
            storage(&fixture),
            0,
            false,
            "replay-test",
            &mut Out::new(&mut |_| Ok(())),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "replay limit must be at least 1");
    }
    #[test]
    fn display_queries_keep_annotations_and_skip_undecodable_parts() {
        use crate::blockdag;
        use triblespace::prelude::{entity, fucid};

        let fixture = fixture();
        let fact = blockdag::text_fact(
            archive_schema::content_fact::modality::TEXT,
            archive_schema::content_fact::direction::IN,
            "readable body",
        )
        .unwrap();
        let fact_id = fact.root().unwrap();
        let part = blockdag::content_part(0, fact, None).unwrap();
        let block = blockdag::block([], None, part).unwrap();
        let block_id = block.root().unwrap();
        let mut fragment = blockdag::source_projection(
            archive_schema::source_projection::SOURCE_CODEX,
            "annotated/source",
            b"exact raw record".to_vec(),
            block,
        )
        .unwrap();
        let projection = fragment.root().unwrap();
        fragment += entity! { triblespace::core::id::ExclusiveId::force_ref(&projection) @
            archive_schema::source_projection::raw_author*: ["one author", "another author"],
            metadata::name: "unmodeled annotation",
        };
        fragment += entity! { triblespace::core::id::ExclusiveId::force_ref(&fact_id) @
            archive_schema::content_fact::asset_pointer: "also an external interpretation",
        };
        let undecodable = fucid();
        fragment += entity! { &undecodable @
            archive_schema::content_part::ordinal: u128::MAX,
            archive_schema::content_part::fact: fact_id,
        };
        fragment += entity! { triblespace::core::id::ExclusiveId::force_ref(&block_id) @
            archive_schema::block::contains: &undecodable,
        };
        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        let collection = open_configured(
            &mut pile,
            archive_schema::DEFAULT_SCOPE_ID,
            signer.verifying_key(),
        )
        .unwrap();
        pile.commit(collection, &signer, fragment).unwrap();
        pile.close().unwrap();

        let observed = storage(&fixture).load().unwrap();
        let facts = observed.view::<FactArchive>().unwrap();
        let rendered = render_projection(&facts, observed.snapshot(), projection).unwrap();
        assert!(rendered.contains("one author"));
        assert!(rendered.contains("another author"));
        assert!(rendered.contains("readable body"));
        assert!(rendered.contains("also an external interpretation"));
        assert_eq!(rendered.matches("part[").count(), 1);
        let summary = render_projection_summary(&facts, observed.snapshot(), projection).unwrap();
        assert!(summary.contains("readable body"));
    }
}
