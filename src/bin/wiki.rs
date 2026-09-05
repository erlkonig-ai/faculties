use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::clock;
use faculties::collection_names::{configured_handle, open_configured, open_exact_in};
#[cfg(feature = "local-embed")]
use faculties::schemas::embeddings::{self, Embedding768};
use faculties::schemas::files::DEFAULT_SCOPE_ID as FILES_SCOPE_ID;
use faculties::schemas::wiki::{self as schema, extract_link_targets};
use faculties::storage::{load_signer, open_store, read, runtime, FactArchive, FacultyStore};
use faculties::wiki::{
    self as wiki_model, EntryRecord, FrontierModel, LinkClass, LinkReference, RevisionDraft,
    RevisionRecord,
};
#[cfg(test)]
use hifitime::Epoch;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::observed_union::ObservedIndex;
use triblespace::core::collection::{CollectionCommit, CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::{SnapshotSource, StorageClose, StoreSnapshot};
use triblespace::prelude::*;

#[cfg(feature = "local-embed")]
/// Shared embedding scope minted with trible genid on 2026-08-09 and retained
/// from commit 4aa344f7 in the collection-port lineage.
const EMBEDDINGS_SCOPE_ID: Id = triblespace::macros::id_hex!("F6BE4C16A56001FEA03A5927C6ED3814");

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "wiki",
    about = "A fork-visible knowledge wiki over a signed revision-DAG collection"
)]
struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Create an unanchored native entry.
    Create {
        title: String,
        /// Content text. Use @path or @-.
        content: String,
        #[arg(long)]
        tag: Vec<String>,
        /// Permit well-formed links whose targets are not present yet.
        #[arg(long)]
        force: bool,
    },
    /// Join an entry's complete current frontier with a successor revision.
    Edit {
        id: String,
        content: Option<String>,
        #[arg(long)]
        title: Option<String>,
        /// Replacement tag set; omitted means inherit the agreed current set.
        #[arg(long)]
        tag: Vec<String>,
        #[arg(long)]
        force: bool,
    },
    /// Show what an id's entry says NOW, following the revision forward.
    ///
    /// A citation names a revision — immutable, pinned to the text its author
    /// read — and `wiki lint` deliberately never rewrites one forward, so a
    /// corpus that links liberally accumulates pinned ids the frontier has
    /// since moved past. Following the entry is therefore the reading a reader
    /// almost always wants, and it was behind an opt-in flag until 2026-08-27.
    /// Per citation carried by one production pile's live frontier
    /// (3264 entries, `cargo run --example reference_census`): 11823 of 14555
    /// (81.2%) named a superseded revision, and 99.6% of those carry text
    /// DIFFERING from what their entry says today. Freezing by default made
    /// that a silent wrong answer that looks exactly like a right one.
    ///
    /// `--exact` opts back into the frozen revision, for inspecting history.
    /// A forked entry prints every head rather than choosing one.
    Show {
        id: String,
        /// Show the named revision itself, not its entry's current frontier.
        #[arg(long)]
        exact: bool,
    },
    /// Print content without a metadata header. Fails on a fork.
    ///
    /// Follows the entry forward exactly as `show` does, so the two never
    /// disagree about what one id says; `--exact` pins the named revision.
    Export {
        id: String,
        /// Print the named revision itself, not its entry's current frontier.
        #[arg(long)]
        exact: bool,
    },
    /// Compare two deterministically ordered revisions in an entry.
    Diff {
        id: String,
        #[arg(long)]
        from: Option<usize>,
        #[arg(long)]
        to: Option<usize>,
    },
    Archive {
        id: String,
    },
    Restore {
        id: String,
    },
    Revert {
        id: String,
        #[arg(long)]
        to: usize,
    },
    /// Audit every frontier link, or show one entry's links when given an id.
    ///
    /// With no id this classifies the whole live frontier's citations: a
    /// target that never existed is a forward reference, one whose entry is
    /// archived is real breakage, and a legacy fragment anchor is a migration
    /// signal. Diagnostic by default; `--strict` is the opt-in exit code.
    ///
    /// With an id, incoming links are revision-scoped: a citation records what
    /// its author read, so a superseded revision that cited this page is still
    /// listed. `wiki show <revision>` says whether the citation survived.
    Links {
        id: Option<String>,
        /// Rows to print per class, and unreferenced entries to name.
        #[arg(long, default_value = "15")]
        top: usize,
        /// Exit non-zero when a link points into an archived entry. OPT-IN:
        /// nothing else here ever fails, forward references least of all.
        #[arg(long)]
        strict: bool,
    },
    List {
        #[arg(long)]
        tag: Vec<String>,
        #[arg(long)]
        with_backlink_tag: Vec<String>,
        #[arg(long)]
        without_backlink_tag: Vec<String>,
        #[arg(long)]
        with_backlink_type: Vec<String>,
        #[arg(long)]
        without_backlink_type: Vec<String>,
        #[arg(long)]
        all: bool,
    },
    History {
        id: String,
    },
    Tag {
        #[command(subcommand)]
        command: TagCommand,
    },
    Import {
        path: PathBuf,
        #[arg(long)]
        tag: Vec<String>,
    },
    Search {
        query: String,
        #[arg(long, short = 'c')]
        context: bool,
        #[arg(long)]
        all: bool,
    },
    /// Write missing vectors into the shared embedding collection.
    Embed,
    /// Rebuild an in-memory nearest-neighbour search from the shared collection.
    Similar {
        query: String,
    },
    Batch {
        #[command(subcommand)]
        action: BatchAction,
    },
    Check {
        #[arg(long)]
        compile: bool,
    },
    /// Resolve one scheme:prefix line per input line.
    FixTruncated {
        input: String,
    },
    /// Apply markdown-to-Typst and reference normalization.
    Lint {
        #[arg(long)]
        fix: bool,
        #[arg(long)]
        check: bool,
    },
}

#[derive(Subcommand)]
enum TagCommand {
    Add { id: String, name: String },
    Remove { id: String, name: String },
    List,
    Mint { name: String },
}

#[derive(Subcommand)]
enum BatchAction {
    Export { dir: PathBuf },
    Import { dir: PathBuf },
}

#[derive(Clone, Copy)]
struct WikiStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

#[derive(Clone)]
struct WikiView {
    facts: FactArchive,
    reader: PileSnapshot,
    observed: ObservedIndex,
}

impl WikiStorage<'_> {
    fn with_pile<T>(
        &self,
        f: impl FnOnce(
            &mut FacultyStore,
            &ed25519_dalek::SigningKey,
            &tokio::runtime::Runtime,
        ) -> Result<T>,
    ) -> Result<T> {
        let signer = load_signer(self.pile, self.key)?;
        let runtime = runtime()?;
        let mut pile = open_store(self.pile)?;
        let result = f(&mut pile, &signer, &runtime);
        let close = pile.close();
        match (result, close) {
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) => Err(anyhow!("close Wiki pile: {error}")),
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(close_error)) => {
                Err(error.context(format!("closing Wiki pile also failed: {close_error}")))
            }
        }
    }

    /// Freeze the query relations once, then acquire only selected payloads
    /// while preparing a result. Output, model work, and publication belong
    /// after this returns: only the pure preparation may be retried.
    fn views<T>(
        &self,
        scopes: &[(Id, &str)],
        mut prepare: impl FnMut(&WikiView, &[FactArchive]) -> Result<T>,
    ) -> Result<T> {
        self.with_pile(|pile, signer, runtime| {
            runtime.block_on(async {
                let authority = signer.verifying_key();
                let wiki_source = open_source(pile, schema::DEFAULT_SCOPE_ID, authority).await?;
                let descriptors = pile
                    .snapshot()
                    .context("freeze Wiki source policy snapshot")?;
                let policy = wiki_source
                    .policy(&descriptors)
                    .context("read Wiki source policy")?;
                drop(descriptors);
                let wiki_succinct = pile
                    .derive::<SuccinctArchiveBlob>(wiki_source, (), policy.clone())
                    .context("register Wiki Succinct collection")?;
                let wiki_rank9 = pile
                    .derive::<Rank9AcceleratedSuccinctArchiveBlob>(wiki_succinct, (), policy)
                    .context("register Wiki Rank9 collection")?;
                let observed = wiki_model::observed_collection(pile, authority)?;
                let mut auxiliaries = Vec::with_capacity(scopes.len());
                for &(scope, label) in scopes {
                    let source = open_source(pile, scope, authority).await?;
                    let descriptors = pile
                        .snapshot()
                        .with_context(|| format!("freeze {label} source policy snapshot"))?;
                    let policy = source
                        .policy(&descriptors)
                        .with_context(|| format!("read {label} source policy"))?;
                    drop(descriptors);
                    let succinct = pile
                        .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
                        .with_context(|| format!("register {label} Succinct collection"))?;
                    let rank9 = pile
                        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
                        .with_context(|| format!("register {label} Rank9 collection"))?;
                    auxiliaries.push((source, succinct, rank9, label));
                }
                drop(
                    pile.ensure(wiki_source)
                        .await
                        .context("ensure Wiki source collection")?,
                );
                for (source, _, _, label) in &auxiliaries {
                    drop(
                        pile.ensure(*source)
                            .await
                            .with_context(|| format!("ensure {label} source collection"))?,
                    );
                }
                drop(
                    pile.maintain(wiki_succinct)
                        .await
                        .context("maintain Wiki Succinct collection")?,
                );
                drop(
                    pile.maintain(wiki_rank9)
                        .await
                        .context("maintain Wiki Rank9 collection")?,
                );
                for (_, succinct, rank9, label) in &auxiliaries {
                    drop(
                        pile.maintain(*succinct)
                            .await
                            .with_context(|| format!("maintain {label} Succinct collection"))?,
                    );
                    drop(
                        pile.maintain(*rank9)
                            .await
                            .with_context(|| format!("maintain {label} Rank9 collection"))?,
                    );
                }

                // The supersession index must describe exactly the Wiki facts
                // selected here, not every foundational member known upstream.
                let selected = pile
                    .snapshot()
                    .context("freeze realized Wiki fact selection")?;
                let wiki_support = selected
                    .collection(wiki_rank9)
                    .context("select realized Wiki fact support")?
                    .support()
                    .clone();
                let instant = selected.instant();
                drop(selected);
                drop(
                    pile.maintain_exact(observed, &wiki_support)
                        .await
                        .context("maintain Wiki supersession index")?,
                );

                // Attach every maintained view from one later snapshot. No
                // command can accidentally combine Wiki facts from one revision
                // of the pile with Files or Embeddings from another.
                let reader = pile
                    .snapshot_at(instant)
                    .context("freeze maintained Wiki and auxiliary snapshot")?;
                let facts = reader
                    .collection_exact(wiki_rank9, &wiki_support)
                    .context("observe Wiki fact collection")?
                    .view::<FactArchive>()
                    .context("read Wiki fact collection")?;
                let observed = reader
                    .collection_exact(observed, &wiki_support)
                    .context("observe Wiki supersession index")?
                    .view::<ObservedIndex>()
                    .context("read Wiki supersession index")?;
                let mut auxiliary_facts = Vec::with_capacity(auxiliaries.len());
                for (_, _, rank9, label) in &auxiliaries {
                    auxiliary_facts.push(
                        reader
                            .collection(*rank9)
                            .with_context(|| format!("observe {label} fact collection"))?
                            .view::<FactArchive>()
                            .with_context(|| format!("read {label} fact collection"))?,
                    );
                }
                let mut view = WikiView {
                    facts,
                    reader,
                    observed,
                };
                let snapshot = view.reader.clone();
                read(pile, &snapshot, |reader| {
                    // New bytes may be resident, but the fact archives and
                    // exact observed order never select a newer frontier.
                    view.reader = reader.clone();
                    prepare(&view, &auxiliary_facts)
                })
                .await
            })
        })
    }

    fn view<T>(&self, mut prepare: impl FnMut(&WikiView) -> Result<T>) -> Result<T> {
        self.views(&[], |wiki, _| prepare(wiki))
    }

    fn view_with_scope<T>(
        &self,
        scope: Id,
        label: &str,
        mut prepare: impl FnMut(&WikiView, &FactArchive) -> Result<T>,
    ) -> Result<T> {
        self.views(&[(scope, label)], |wiki, facts| prepare(wiki, &facts[0]))
    }

    #[cfg(feature = "local-embed")]
    fn publish_scope(&self, scope: Id, fragment: Fragment) -> Result<CollectionCommit> {
        self.with_pile(|pile, signer, runtime| {
            let collection = runtime.block_on(open_source(pile, scope, signer.verifying_key()))?;
            pile.commit(collection, signer, fragment)
                .context("publish native collection fragment")
        })
    }

    fn publish(&self, fragment: Fragment) -> Result<CollectionCommit> {
        self.with_pile(|pile, signer, runtime| {
            let collection = runtime.block_on(open_source(
                pile,
                schema::DEFAULT_SCOPE_ID,
                signer.verifying_key(),
            ))?;
            pile.commit(collection, signer, fragment)
                .context("publish Wiki fragment")
        })
    }

    fn author_fragment(&self) -> Result<(Fragment, Id)> {
        let signer = load_signer(self.pile, self.key)?;
        Ok(wiki_model::author_record(&signer.verifying_key()))
    }
}

async fn open_source(
    pile: &mut FacultyStore,
    scope: Id,
    authority: ed25519_dalek::VerifyingKey,
) -> Result<Collection<blobencodings::SimpleArchive>> {
    if let Some(handle) = configured_handle(scope)? {
        let snapshot = pile.snapshot()?;
        read(pile, &snapshot, |reader| {
            open_exact_in(reader, scope, handle)
        })
        .await
    } else {
        open_configured(pile, scope, authority)
    }
}

fn now_interval() -> Result<Inline<inlineencodings::NsTAIInterval>> {
    clock::point_now()
}

fn entry_label(entry: &EntryRecord) -> String {
    entry
        .roots
        .first()
        .map(|id| format!("{id:x}"))
        .unwrap_or_else(|| "<empty>".to_owned())
}

/// Every id the CLI accepts. A revision, and nothing else: the legacy anchor
/// stopped being a selector on 2026-08-18, so an anchor id now matches nothing
/// rather than silently naming whatever text is current.
fn all_selectors<P: TriblePattern>(facts: &P) -> BTreeSet<Id> {
    wiki_model::revision_ids(facts)
}

fn resolve_prefix<P: TriblePattern>(facts: &P, raw: &str) -> Result<Id> {
    let clean = raw.trim().to_ascii_lowercase();
    if clean.is_empty() || clean.len() > 32 || !clean.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid Wiki selector '{raw}'");
    }
    let candidates = all_selectors(facts);
    let matches: Vec<Id> = candidates
        .into_iter()
        .filter(|id| format!("{id:x}").starts_with(&clean))
        .collect();
    match matches.as_slice() {
        [] => bail!("no Wiki id matches '{raw}'"),
        [only] => Ok(*only),
        many => bail!("ambiguous Wiki id '{raw}' ({} matches)", many.len()),
    }
}

/// Resolve a selector to the revisions a command should act on.
///
/// `follow_frontier` is the read-side policy: true asks the ENTRY what it says
/// now — which may be several heads on a fork — and false pins the one named
/// revision. Mutations resolve exact here and then join the whole frontier
/// through [`mutation_entry`], so a write already follows the entry no matter
/// which member id it is handed.
fn selector_revisions(
    view: &WikiView,
    selector: Id,
    follow_frontier: bool,
) -> Result<Vec<RevisionRecord>> {
    let revisions = wiki_model::revision_records(&view.facts, selector);
    if revisions.is_empty() {
        bail!("unknown Wiki selector {selector:x}");
    }
    if follow_frontier {
        Ok(wiki_model::entry(&view.facts, &view.observed, selector)
            .expect("queryable revision belongs to one entry")
            .frontier)
    } else {
        Ok(revisions)
    }
}

fn mutation_entry(view: &WikiView, raw: &str) -> Result<EntryRecord> {
    let selector = resolve_prefix(&view.facts, raw)?;
    wiki_model::entry(&view.facts, &view.observed, selector)
        .ok_or_else(|| anyhow!("unknown Wiki selector {selector:x}"))
}

fn read_string(reader: &PileSnapshot, handle: schema::TextHandle) -> Result<String> {
    wiki_model::read_text(reader, handle)
}

fn tag_name<P: TriblePattern>(facts: &P, reader: &PileSnapshot, id: Id) -> Result<String> {
    let mut names = BTreeSet::new();
    for handle in find!(
        handle: schema::TextHandle,
        pattern!(facts, [{ id @ metadata::name: ?handle }])
    ) {
        names.insert(read_string(reader, handle)?);
    }
    Ok(if names.is_empty() {
        schema::TAG_SPECS
            .iter()
            .find_map(|(known, label)| (*known == id).then_some((*label).to_owned()))
            .unwrap_or_else(|| format!("{id:x}"))
    } else {
        names.into_iter().collect::<Vec<_>>().join(" / ")
    })
}

fn tag_ids_named<P: TriblePattern>(
    facts: &P,
    reader: &PileSnapshot,
    wanted: &str,
) -> Result<BTreeSet<Id>> {
    let wanted = wanted.trim();
    let mut ids = BTreeSet::new();
    for (id, handle) in find!(
        (id: Id, handle: schema::TextHandle),
        pattern!(facts, [{ ?id @ metadata::name: ?handle }])
    ) {
        if read_string(reader, handle)?.eq_ignore_ascii_case(wanted) {
            ids.insert(id);
        }
    }
    Ok(ids)
}

fn format_tags<P: TriblePattern>(
    facts: &P,
    reader: &PileSnapshot,
    tags: &BTreeSet<Id>,
) -> Result<String> {
    let mut names = Vec::new();
    for tag in tags {
        names.push(tag_name(facts, reader, *tag)?);
    }
    Ok(if names.is_empty() {
        String::new()
    } else {
        format!(" [{}]", names.join(", "))
    })
}

fn resolve_tags<P: TriblePattern>(
    facts: &P,
    reader: &PileSnapshot,
    names: &[String],
    fragment: &mut Fragment,
) -> Result<BTreeSet<Id>> {
    if names.is_empty() {
        return Ok(BTreeSet::new());
    }
    let mut by_name: BTreeMap<String, BTreeSet<Id>> = BTreeMap::new();
    for (id, handle) in find!(
        (id: Id, handle: schema::TextHandle),
        pattern!(facts, [{ ?id @ metadata::name: ?handle }])
    ) {
        by_name
            .entry(read_string(reader, handle)?.to_ascii_lowercase())
            .or_default()
            .insert(id);
    }
    let mut out = BTreeSet::new();
    for raw in names {
        let name = raw.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        if let Some(ids) = by_name.get(&name) {
            out.extend(ids.iter().copied());
        } else {
            let (record, id, _) = wiki_model::tag_record(&name)?;
            *fragment += record;
            by_name.insert(name, BTreeSet::from([id]));
            out.insert(id);
        }
    }
    Ok(out)
}

fn agreed<T: Clone + Eq>(
    entry: &EntryRecord,
    field: impl Fn(&RevisionRecord) -> T,
    name: &str,
) -> Result<T> {
    let first = entry.frontier.first().expect("entry frontier is non-empty");
    let value = field(first);
    if entry
        .frontier
        .iter()
        .skip(1)
        .any(|head| field(head) != value)
    {
        bail!("entry frontier disagrees on {name}; supply a complete resolution explicitly");
    }
    Ok(value)
}

fn stage_revision(
    storage: WikiStorage<'_>,
    fragment: &mut Fragment,
    entry: Option<&EntryRecord>,
    title: String,
    content: String,
    tags: BTreeSet<Id>,
) -> Result<Id> {
    let (author_fragment, author) = storage.author_fragment()?;
    *fragment += author_fragment;
    let predecessors = entry
        .map(|entry| entry.frontier.iter().map(|head| head.id).collect())
        .unwrap_or_default();
    let (record, revision) = wiki_model::revision_record(RevisionDraft {
        title,
        content,
        tags,
        predecessors,
        author,
        authored_at: now_interval()?,
    })?;
    *fragment += record;
    Ok(revision)
}

fn known_link_ids<P: TriblePattern>(facts: &P) -> BTreeSet<Id> {
    all_selectors(facts)
}

fn validate_links<P: TriblePattern>(content: &str, facts: &P, allow_dangling: bool) -> Result<()> {
    let known = known_link_ids(facts);
    let mut failures = Vec::new();
    let re = regex::Regex::new(r"wiki:(?:[A-Za-z_][A-Za-z0-9_]*:)?([0-9A-Fa-f]+)").unwrap();
    for captures in re.captures_iter(content) {
        let token = &captures[1];
        if token.len() != 32 {
            failures.push(format!("truncated link wiki:{token}"));
        } else if let Some(id) = Id::from_hex(token) {
            if !known.contains(&id) && !allow_dangling {
                failures.push(format!("broken link wiki:{token}"));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!("Wiki link validation failed:\n  {}", failures.join("\n  "))
    }
}

struct ReferenceResolver<'a, P: TriblePattern> {
    wiki: &'a P,
    files: Option<&'a P>,
}

impl<P: TriblePattern> Copy for ReferenceResolver<'_, P> {}

impl<P: TriblePattern> Clone for ReferenceResolver<'_, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: TriblePattern> ReferenceResolver<'_, P> {
    fn expand(&self, scheme: &str, rest: &str) -> Result<String> {
        match scheme {
            // A Wiki reference names a REVISION: immutable, pinned to the text
            // its author read. Legacy anchors resolved here until 2026-08-18 —
            // `wiki lint` rewrote every anchor reference in the corpus to the
            // anchor's then-current head first — and now an anchor id simply
            // does not resolve, so a reference that survives is left as it is
            // and `wiki check` reports it broken rather than following it.
            "wiki" => {
                let (kind, hex) = split_typed(rest);
                Ok(format!("{kind}{:x}", resolve_prefix(self.wiki, hex)?))
            }
            "files" => {
                if rest.contains(':') {
                    bail!("files references do not have typed targets");
                }
                let clean = rest.trim().to_ascii_lowercase();
                let reference = match self.files {
                    Some(files) => faculties::files::resolve_reference(files, &clean),
                    None if clean.len() == 32 || clean.len() == 64 => {
                        faculties::files::resolve_reference(&TribleSet::new(), &clean)
                    }
                    None => {
                        bail!("cannot resolve short files selector without the Files collection")
                    }
                }?;
                Ok(reference.hex())
            }
            _ => bail!("unknown reference scheme '{scheme}'"),
        }
    }
}

fn split_typed(rest: &str) -> (String, &str) {
    if let Some((kind, hex)) = rest.split_once(':') {
        if !kind.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return (format!("{kind}:"), hex);
        }
    }
    (String::new(), rest)
}

fn lint_fix<P: TriblePattern>(content: &str, resolver: ReferenceResolver<'_, P>) -> String {
    let mut output = String::with_capacity(content.len());
    let mut fenced = false;
    for line in content.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
        }
        let line = if fenced {
            line.to_owned()
        } else {
            lint_line(line, resolver)
        };
        output.push_str(&line);
        output.push('\n');
    }
    if !content.ends_with('\n') {
        output.pop();
    }
    output
}

fn regexes() -> &'static LintPatterns {
    static PATTERNS: OnceLock<LintPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| LintPatterns {
        bold: regex::Regex::new(r"\*\*([^*]+)\*\*").unwrap(),
        markdown_links: regex::Regex::new(
            r"\[([^\]]+)\]\((wiki|files):((?:[A-Za-z_][A-Za-z0-9_]*:)?[0-9A-Fa-f]+)\)",
        )
        .unwrap(),
        web_links: regex::Regex::new(r"\[([^\]]+)\]\((https?://[^)]+)\)").unwrap(),
        wiki_references: regex::Regex::new(r"wiki:((?:[A-Za-z_][A-Za-z0-9_]*:)?[0-9A-Fa-f]+)\b")
            .unwrap(),
    })
}

struct LintPatterns {
    bold: regex::Regex,
    markdown_links: regex::Regex,
    web_links: regex::Regex,
    wiki_references: regex::Regex,
}

fn lint_line<P: TriblePattern>(line: &str, resolver: ReferenceResolver<'_, P>) -> String {
    let patterns = regexes();
    let line = if let Some(rest) = line.strip_prefix("### ") {
        format!("=== {rest}")
    } else if let Some(rest) = line.strip_prefix("## ") {
        format!("== {rest}")
    } else if let Some(rest) = line.strip_prefix("# ") {
        format!("= {rest}")
    } else {
        line.to_owned()
    };
    let line = patterns.bold.replace_all(&line, "*$1*").to_string();
    let line = patterns
        .markdown_links
        .replace_all(&line, |captures: &regex::Captures| {
            let scheme = &captures[2];
            let rest = &captures[3];
            let resolved = resolver
                .expand(scheme, rest)
                .unwrap_or_else(|_| rest.to_ascii_lowercase());
            format!("#link(\"{scheme}:{resolved}\")[{}]", &captures[1])
        })
        .to_string();
    let line = patterns
        .web_links
        .replace_all(&line, "#link(\"$2\")[$1]")
        .to_string();
    // Every remaining `wiki:` reference — a Typst link target, a link LABEL
    // that repeats the id, a bare prose mention — names its target the same
    // way. This is what retires the legacy anchors: an anchor becomes the
    // citation it always stood for (its current head revision), a truncated
    // prefix becomes the full id, and anything that already names a revision
    // keeps its exact bytes, so a wiki of citations is a fixpoint of the pass.
    let line = patterns
        .wiki_references
        .replace_all(&line, |captures: &regex::Captures| {
            let rest = &captures[1];
            match resolver.expand("wiki", rest) {
                Ok(resolved) if !resolved.eq_ignore_ascii_case(rest) => format!("wiki:{resolved}"),
                _ => captures[0].to_owned(),
            }
        })
        .to_string();
    if matches!(line.trim(), "---" | "***" | "___") {
        String::new()
    } else {
        line
    }
}

fn validate_typst(content: &str) -> Result<()> {
    let world = typst_validate::ValidateWorld::new(content);
    world
        .validate()
        .map_err(|errors| anyhow!("typst compilation failed:\n{}", errors.join("\n")))
}

fn prepare_content(
    raw: &str,
    wiki: &FactArchive,
    files: Option<&FactArchive>,
    allow_dangling: bool,
) -> Result<String> {
    let content = lint_fix(raw, ReferenceResolver { wiki, files });
    validate_typst(&content)?;
    validate_links(&content, wiki, allow_dangling)?;
    Ok(content)
}

fn revision_title(reader: &PileSnapshot, revision: &RevisionRecord) -> Result<String> {
    read_string(reader, revision.title)
}

fn revision_content(reader: &PileSnapshot, revision: &RevisionRecord) -> Result<String> {
    read_string(reader, revision.content)
}

fn cmd_create(
    storage: WikiStorage<'_>,
    title: String,
    content: String,
    tags: Vec<String>,
    force: bool,
) -> Result<()> {
    let title = faculties::text_arg(&title, "title")?;
    let raw = faculties::text_arg(&content, "content")?;
    let (content, tags, mut fragment) =
        storage.view_with_scope(FILES_SCOPE_ID, "Files", |view, files| {
            let content = prepare_content(&raw, &view.facts, Some(files), force)?;
            let mut fragment = Fragment::empty();
            let tags = resolve_tags(&view.facts, &view.reader, &tags, &mut fragment)?;
            Ok((content, tags, fragment))
        })?;
    let revision = stage_revision(storage, &mut fragment, None, title, content, tags)?;
    storage.publish(fragment)?;
    println!("revision {revision:x}");
    Ok(())
}

fn cmd_edit(
    storage: WikiStorage<'_>,
    id: String,
    content: Option<String>,
    title: Option<String>,
    tag_names: Vec<String>,
    force: bool,
) -> Result<()> {
    let title = title
        .map(|value| faculties::text_arg(&value, "title"))
        .transpose()?;
    let content = content
        .map(|value| faculties::text_arg(&value, "content"))
        .transpose()?;
    let scopes = if content.is_some() {
        vec![(FILES_SCOPE_ID, "Files")]
    } else {
        Vec::new()
    };
    let (entry, title, content, tags, mut fragment) = storage.views(&scopes, |view, files| {
        let entry = mutation_entry(view, &id)?;
        if content.is_none() && title.is_none() && tag_names.is_empty() && entry.frontier.len() == 1
        {
            bail!("nothing to change");
        }
        let title = match &title {
            Some(value) => value.clone(),
            None => read_string(&view.reader, agreed(&entry, |head| head.title, "title")?)?,
        };
        let content = match &content {
            Some(raw) => prepare_content(raw, &view.facts, files.first(), force)?,
            None => read_string(
                &view.reader,
                agreed(&entry, |head| head.content, "content")?,
            )?,
        };
        let mut fragment = Fragment::empty();
        let tags = if tag_names.is_empty() {
            agreed(&entry, |head| head.tags.clone(), "tags")?
        } else {
            resolve_tags(&view.facts, &view.reader, &tag_names, &mut fragment)?
        };
        Ok((entry, title, content, tags, fragment))
    })?;
    let revision = stage_revision(storage, &mut fragment, Some(&entry), title, content, tags)?;
    storage.publish(fragment)?;
    println!("revision {revision:x}");
    Ok(())
}

fn render_revision(
    facts: &FactArchive,
    reader: &PileSnapshot,
    revision: &RevisionRecord,
) -> Result<String> {
    let mut report = String::new();
    let title = revision_title(reader, revision)?;
    writeln!(report, "# {title}").unwrap();
    writeln!(report, "revision: {:x}", revision.id).unwrap();
    if !revision.supersedes.is_empty() {
        writeln!(
            report,
            "supersedes: {}",
            revision
                .supersedes
                .iter()
                .map(|id| format!("{id:x}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .unwrap();
    }
    let tags = format_tags(facts, reader, &revision.tags)?;
    if !tags.is_empty() {
        writeln!(report, "tags:{tags}").unwrap();
    }
    report.push('\n');
    report.push_str(&revision_content(reader, revision)?);
    Ok(report)
}

fn cmd_show(storage: WikiStorage<'_>, id: String, exact: bool) -> Result<()> {
    let report = storage.view(|view| {
        let selector = resolve_prefix(&view.facts, &id)?;
        let revisions = selector_revisions(view, selector, !exact)?;
        let mut report = String::new();
        // A forked entry has no single current text, so print EVERY head under a
        // banner naming them. Silently picking one would be the same class of
        // wrong answer this command's default exists to remove — indistinguishable
        // from a correct one, and only discovered later by an edit that disagrees.
        if revisions.len() > 1 {
            writeln!(
                report,
                "fork: {} current revisions ({}); all shown, --exact pins one",
                revisions.len(),
                revisions
                    .iter()
                    .map(|revision| format!("{:x}", revision.id))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .unwrap();
        }
        for (index, revision) in revisions.iter().enumerate() {
            if index > 0 {
                report.push_str("\n---\n\n");
            }
            report.push_str(&render_revision(&view.facts, &view.reader, revision)?);
        }
        Ok(report)
    })?;
    print!("{report}");
    Ok(())
}

fn cmd_export(storage: WikiStorage<'_>, id: String, exact: bool) -> Result<()> {
    let content = storage.view(|view| {
        let selector = resolve_prefix(&view.facts, &id)?;
        let revisions = selector_revisions(view, selector, !exact)?;
        let [revision] = revisions.as_slice() else {
            bail!(
                "selector resolves to a fork ({}); choose one with --exact",
                revisions
                    .iter()
                    .map(|revision| format!("{:x}", revision.id))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        revision_content(&view.reader, revision)
    })?;
    print!("{content}");
    Ok(())
}

fn unified_diff(old: &str, new: &str) -> Vec<String> {
    let old: Vec<&str> = old.lines().collect();
    let new: Vec<&str> = new.lines().collect();
    let mut out = Vec::new();
    let count = old.len().max(new.len());
    for index in 0..count {
        match (old.get(index), new.get(index)) {
            (Some(left), Some(right)) if left == right => out.push(format!(" {left}")),
            (Some(left), Some(right)) => {
                out.push(format!("-{left}"));
                out.push(format!("+{right}"));
            }
            (Some(left), None) => out.push(format!("-{left}")),
            (None, Some(right)) => out.push(format!("+{right}")),
            (None, None) => {}
        }
    }
    out
}

fn cmd_diff(
    storage: WikiStorage<'_>,
    id: String,
    from: Option<usize>,
    to: Option<usize>,
) -> Result<()> {
    let report = storage.view(|view| {
        let entry = mutation_entry(view, &id)?;
        let rows = wiki_model::entry_history(&view.facts, &entry);
        if rows.len() < 2 {
            bail!("entry has only {} revision(s)", rows.len());
        }
        let left = from.unwrap_or(rows.len() - 1).saturating_sub(1);
        let right = to.unwrap_or(rows.len()).saturating_sub(1);
        let Some(old) = rows.get(left) else {
            bail!("--from is out of range")
        };
        let Some(new) = rows.get(right) else {
            bail!("--to is out of range")
        };
        let mut report = String::new();
        writeln!(
            report,
            "--- {} {}",
            old.id,
            revision_title(&view.reader, old)?
        )
        .unwrap();
        writeln!(
            report,
            "+++ {} {}",
            new.id,
            revision_title(&view.reader, new)?
        )
        .unwrap();
        for line in unified_diff(
            &revision_content(&view.reader, old)?,
            &revision_content(&view.reader, new)?,
        ) {
            writeln!(report, "{line}").unwrap();
        }
        Ok(report)
    })?;
    print!("{report}");
    Ok(())
}

fn mutate_tags(storage: WikiStorage<'_>, id: String, name: &str, add: bool) -> Result<()> {
    let normalized = name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        bail!("tag name cannot be empty");
    }
    let prepared = storage.view(|view| {
        let entry = mutation_entry(view, &id)?;
        let mut fragment = Fragment::empty();
        let mut tags: BTreeSet<Id> = agreed(&entry, |head| head.tags.clone(), "tags")?
            .into_iter()
            .collect();
        let desired = if add {
            resolve_tags(
                &view.facts,
                &view.reader,
                std::slice::from_ref(&normalized),
                &mut fragment,
            )?
        } else {
            let ids = tag_ids_named(&view.facts, &view.reader, &normalized)?;
            if ids.is_empty() {
                bail!("unknown tag '{normalized}'");
            }
            ids
        };
        let changed = if add {
            let before = tags.len();
            tags.extend(desired);
            tags.len() != before
        } else {
            let before = tags.len();
            for id in desired {
                tags.remove(&id);
            }
            tags.len() != before
        };
        if !changed {
            return Ok(None);
        }
        let title = read_string(&view.reader, agreed(&entry, |head| head.title, "title")?)?;
        let content = read_string(
            &view.reader,
            agreed(&entry, |head| head.content, "content")?,
        )?;
        Ok(Some((entry, title, content, tags, fragment)))
    })?;
    let Some((entry, title, content, tags, mut fragment)) = prepared else {
        println!(
            "already {} #{normalized}",
            if add { "tagged" } else { "untagged" }
        );
        return Ok(());
    };
    let revision = stage_revision(storage, &mut fragment, Some(&entry), title, content, tags)?;
    storage.publish(fragment)?;
    println!("revision {revision:x}");
    Ok(())
}

fn cmd_revert(storage: WikiStorage<'_>, id: String, to: usize) -> Result<()> {
    let (entry, title, content, tags) = storage.view(|view| {
        let entry = mutation_entry(view, &id)?;
        let rows = wiki_model::entry_history(&view.facts, &entry);
        let Some(chosen) = rows.get(to.saturating_sub(1)) else {
            bail!("revision index out of range")
        };
        let title = revision_title(&view.reader, chosen)?;
        let content = revision_content(&view.reader, chosen)?;
        let tags = chosen.tags.iter().copied().collect();
        Ok((entry, title, content, tags))
    })?;
    let mut fragment = Fragment::empty();
    let revision = stage_revision(storage, &mut fragment, Some(&entry), title, content, tags)?;
    storage.publish(fragment)?;
    println!("revision {revision:x}");
    Ok(())
}

/// Link targets cited by one immutable revision.
fn revision_links(reader: &PileSnapshot, revision: &RevisionRecord) -> Result<BTreeSet<Id>> {
    let mut out = BTreeSet::new();
    for raw in extract_link_targets(&revision_content(reader, revision)?) {
        if let Some(id) = Id::from_hex(&raw) {
            out.insert(id);
        }
    }
    Ok(out)
}

fn derived_links(reader: &PileSnapshot, entry: &EntryRecord) -> Result<BTreeSet<Id>> {
    let mut out = BTreeSet::new();
    for head in &entry.frontier {
        out.extend(revision_links(reader, head)?);
    }
    Ok(out)
}

#[derive(Default)]
struct BacklinkSummary {
    tags: BTreeSet<Id>,
    types: BTreeSet<String>,
}

/// Invert every revision's citations, one revision at a time.
///
/// A citation is a claim about what its author actually read, so the citing
/// unit is the revision, never the entry that contains it. Summarizing an
/// entry's frontier would attribute a dropped citation to the whole page: if
/// A1 cited X and A2 removed it, an entry-scoped index still reports "A cites
/// X", which A's current text does not say.
fn backlink_summaries(
    reader: &PileSnapshot,
    facts: &FactArchive,
) -> Result<BTreeMap<Id, BacklinkSummary>> {
    let expression = regex::Regex::new(
        r#"#link\("wiki:(?:(?P<kind>[A-Za-z_][A-Za-z0-9_]*):)?(?P<id>[0-9A-Fa-f]{32})"\)"#,
    )
    .expect("static Wiki link expression");
    let mut summaries = BTreeMap::<Id, BacklinkSummary>::new();
    for id in wiki_model::revision_ids(facts) {
        for source in wiki_model::revision_records(facts, id) {
            let content = revision_content(reader, &source)?;
            for captures in expression.captures_iter(&content) {
                let target = Id::from_hex(&captures["id"]).expect("expression matched a full id");
                let summary = summaries.entry(target).or_default();
                summary.tags.extend(source.tags.iter().copied());
                if let Some(kind) = captures.name("kind") {
                    summary.types.insert(kind.as_str().to_ascii_lowercase());
                }
            }
        }
    }
    Ok(summaries)
}

fn cmd_links(storage: WikiStorage<'_>, id: Option<String>, top: usize, strict: bool) -> Result<()> {
    let Some(id) = id else {
        let model =
            storage.view(|view| FrontierModel::load(&view.reader, &view.facts, &view.observed))?;
        return cmd_link_audit(&model, top, strict);
    };
    let (outgoing, incoming) = storage.view(|view| {
        let entry = match mutation_entry(view, &id) {
            Ok(entry) => entry,
            Err(error) => return Err(explain_selector(view, &id, error)?),
        };
        Ok((
            derived_links(&view.reader, &entry)?,
            incoming_revisions(view, &entry)?,
        ))
    })?;
    println!("outgoing:");
    for target in outgoing {
        println!("  {target:x}");
    }
    println!("incoming:");
    for source in incoming {
        println!("  {source:x}");
    }
    Ok(())
}

/// Say WHY an id does not resolve, not merely that it does not.
///
/// An id someone is holding -- out of an old note, a compass goal, a
/// pre-cutover citation -- fails for three different reasons, and "no Wiki id
/// matches" is the same sentence for all of them. Only reached on the failure
/// path, so the ordinary lookup pays nothing for it.
fn explain_selector(view: &WikiView, raw: &str, error: anyhow::Error) -> Result<anyhow::Error> {
    let Some(target) = Id::from_hex(raw.trim()) else {
        return Ok(error);
    };
    let model = FrontierModel::load(&view.reader, &view.facts, &view.observed)?;
    let entry = |index: usize| {
        let entry = &model.entries[index];
        format!("{} [wiki:{:x}]", short(&entry.title(), 55), entry.label)
    };
    let diagnosis = match model.classify(target) {
        LinkClass::Legacy { entries, retired } => format!(
            "it is a LEGACY FRAGMENT ANCHOR for {}{}. Anchors stopped being \
             selectors on 2026-08-18 -- an id names a revision or it names \
             nothing -- so cite a revision of that entry instead.",
            entries
                .iter()
                .map(|index| entry(*index))
                .collect::<Vec<_>>()
                .join(" | "),
            if retired { " (archived)" } else { "" }
        ),
        LinkClass::Unwritten(Some(kind)) => format!(
            "it names a {}, not a page. Nothing in the wiki is addressable by it.",
            kind.label()
        ),
        LinkClass::Unwritten(None) => {
            "no fragment has ever had it, at any revision. If it came from another \
             pile, it is that pile's id and does not travel."
                .to_owned()
        }
        // A resolvable id reaches here only when the selector spans entries.
        LinkClass::Live(index) | LinkClass::Retired(index) => {
            format!("it resolves to {}", entry(index))
        }
        LinkClass::Ambiguous(candidates) => format!(
            "it names several disconnected entries: {}",
            candidates
                .iter()
                .map(|index| entry(*index))
                .collect::<Vec<_>>()
                .join(" | ")
        ),
    };
    Ok(error.context(diagnosis))
}

fn describe_target(model: &FrontierModel, reference: &LinkReference) -> String {
    let entry = |index: usize| {
        let entry = &model.entries[index];
        format!("{} [wiki:{:x}]", short(&entry.title(), 55), entry.label)
    };
    match &reference.class {
        LinkClass::Live(index) | LinkClass::Retired(index) => entry(*index),
        LinkClass::Ambiguous(candidates) => candidates
            .iter()
            .map(|index| entry(*index))
            .collect::<Vec<_>>()
            .join(" | "),
        LinkClass::Legacy { entries, retired } => format!(
            "{}{}",
            entries
                .iter()
                .map(|index| entry(*index))
                .collect::<Vec<_>>()
                .join(" | "),
            if *retired { " (archived)" } else { "" }
        ),
        LinkClass::Unwritten(Some(kind)) => format!("names a {}, not a page", kind.label()),
        LinkClass::Unwritten(None) => "nothing, at any revision".to_owned(),
    }
}

fn print_class(model: &FrontierModel, heading: &str, rows: &[LinkReference], top: usize) {
    if rows.is_empty() {
        return;
    }
    println!("\n--- {heading} ({}) ---", rows.len());
    for reference in rows.iter().take(top) {
        println!(
            "{} [wiki:{:x}]",
            short(&reference.source_title, 60),
            reference.source
        );
        println!(
            "  -> wiki:{:x}  {}",
            reference.target,
            describe_target(model, reference)
        );
    }
    if rows.len() > top {
        println!("  … {} more", rows.len() - top);
    }
}

/// Classify every citation the live frontier makes.
///
/// Diagnostic by design: this reports, it does not gate. The one class that
/// means something broke is a citation into an entry whose every current state
/// is archived; an unwritten target is the wiki's link-liberally convention
/// working as intended, and a legacy anchor is a migration signal.
fn cmd_link_audit(model: &FrontierModel, top: usize, strict: bool) -> Result<()> {
    let audit = model.audit();
    let unreferenced = model.unreferenced(&audit);

    println!("=== WIKI: Frontier Link Audit ===\n");
    println!(
        "Live entries:          {} ({} current states)",
        model.active_count(),
        audit.states
    );
    println!("Outgoing citations:    {}", audit.total);
    println!("  resolve live:        {}", audit.live);
    println!(
        "  ambiguous selector:  {}  (a fork is evidence, not breakage)",
        audit.ambiguous.len()
    );
    println!(
        "  archived target:     {}  <- BROKEN: the frontier dropped it",
        audit.retired.len()
    );
    println!(
        "  legacy anchor only:  {}  <- migration signal, still reachable",
        audit.legacy.len()
    );
    println!(
        "  never written:       {}  <- forward references, a TODO list",
        audit.unwritten.len()
    );
    println!(
        "Legacy anchors indexed: {}  (a zero above means none is CITED, not\n\
         \x20                        that none exists)",
        model.anchor_count()
    );

    print_class(&model, "ARCHIVED TARGETS", &audit.retired, top);
    print_class(&model, "LEGACY ANCHORS", &audit.legacy, top);
    print_class(&model, "NEVER WRITTEN", &audit.unwritten, top);
    print_class(&model, "AMBIGUOUS SELECTORS", &audit.ambiguous, top);

    println!(
        "\n--- UNREFERENCED LIVE ENTRIES ({} of {}) ---",
        unreferenced.len(),
        model.active_count()
    );
    for index in unreferenced.iter().take(top) {
        let entry = &model.entries[*index];
        println!("{} [wiki:{:x}]", short(&entry.title(), 60), entry.label);
    }
    if unreferenced.len() > top {
        println!("  … {} more", unreferenced.len() - top);
    }

    if strict && audit.breakage() > 0 {
        bail!(
            "{} frontier citation(s) point into an archived entry",
            audit.breakage()
        );
    }
    Ok(())
}

fn short(value: &str, chars: usize) -> String {
    value.chars().take(chars).collect()
}

/// Every revision whose own text cites `entry`, superseded revisions included.
///
/// REVISION-scoped by design. An entry-scoped answer asserts a citation that
/// may no longer exist: if A1 cited this page and A2 dropped the citation,
/// naming "A" claims A currently cites it, which A's text denies. Naming A1 is
/// exactly true — A1 did — and `wiki show <A1>`, which follows the entry
/// forward, shows whether A's current text still does.
fn incoming_revisions(view: &WikiView, entry: &EntryRecord) -> Result<Vec<Id>> {
    let target_ids: BTreeSet<Id> = entry.members.iter().copied().collect();
    let mut out = Vec::new();
    for id in wiki_model::revision_ids(&view.facts) {
        for source in wiki_model::revision_records(&view.facts, id) {
            if revision_links(&view.reader, &source)?
                .iter()
                .any(|id| target_ids.contains(id))
            {
                out.push(source.id);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn cmd_list(
    storage: WikiStorage<'_>,
    tag_names: Vec<String>,
    with_backlink_tag: Vec<String>,
    without_backlink_tag: Vec<String>,
    with_backlink_type: Vec<String>,
    without_backlink_type: Vec<String>,
    all: bool,
) -> Result<()> {
    let report = storage.view(|view| {
        let wanted: Vec<BTreeSet<Id>> = tag_names
            .iter()
            .map(|name| tag_ids_named(&view.facts, &view.reader, name))
            .collect::<Result<_>>()?;
        let with_backlink_tags: Vec<BTreeSet<Id>> = with_backlink_tag
            .iter()
            .map(|name| tag_ids_named(&view.facts, &view.reader, name))
            .collect::<Result<_>>()?;
        let without_backlink_tags: Vec<BTreeSet<Id>> = without_backlink_tag
            .iter()
            .map(|name| tag_ids_named(&view.facts, &view.reader, name))
            .collect::<Result<_>>()?;
        for (name, ids) in tag_names
            .iter()
            .zip(&wanted)
            .chain(with_backlink_tag.iter().zip(&with_backlink_tags))
            .chain(without_backlink_tag.iter().zip(&without_backlink_tags))
        {
            if ids.is_empty() {
                bail!("unknown tag '{}'", name.trim());
            }
        }
        let with_backlink_types: Vec<String> = with_backlink_type
            .iter()
            .map(|kind| kind.to_ascii_lowercase())
            .collect();
        let without_backlink_types: Vec<String> = without_backlink_type
            .iter()
            .map(|kind| kind.to_ascii_lowercase())
            .collect();
        let has_backlink_filter = !with_backlink_tags.is_empty()
            || !without_backlink_tags.is_empty()
            || !with_backlink_types.is_empty()
            || !without_backlink_types.is_empty();
        // Only backlink filters need page content, so scan every revision once and
        // invert its links on demand.
        let backlink_summaries = if has_backlink_filter {
            Some(backlink_summaries(&view.reader, &view.facts)?)
        } else {
            None
        };
        let mut entries = wiki_model::entries(&view.facts, &view.observed);
        if !all {
            entries.retain(|entry| {
                !entry
                    .frontier
                    .iter()
                    .all(|revision| revision.tags.contains(&schema::TAG_ARCHIVED_ID))
            });
        }
        let mut report = String::new();
        for entry in entries {
            if !wanted.is_empty()
                && !entry
                    .frontier
                    .iter()
                    .any(|head| wanted.iter().all(|ids| !head.tags.is_disjoint(ids)))
            {
                continue;
            }
            if let Some(backlink_summaries) = &backlink_summaries {
                let mut incoming_tags = BTreeSet::new();
                let mut incoming_types = BTreeSet::new();
                for target in entry.members.iter() {
                    if let Some(summary) = backlink_summaries.get(target) {
                        incoming_tags.extend(summary.tags.iter().copied());
                        incoming_types.extend(summary.types.iter().cloned());
                    }
                }
                if !with_backlink_tags
                    .iter()
                    .all(|ids| !incoming_tags.is_disjoint(ids))
                    || without_backlink_tags
                        .iter()
                        .any(|ids| !incoming_tags.is_disjoint(ids))
                    || !with_backlink_types
                        .iter()
                        .all(|kind| incoming_types.contains(kind))
                    || without_backlink_types
                        .iter()
                        .any(|kind| incoming_types.contains(kind))
                {
                    continue;
                }
            }
            writeln!(
                report,
                "{}{}",
                entry_label(&entry),
                if entry.frontier.len() > 1 {
                    "  [fork]"
                } else {
                    ""
                }
            )
            .unwrap();
            for head in &entry.frontier {
                writeln!(
                    report,
                    "  {:x}  {}{}",
                    head.id,
                    revision_title(&view.reader, head)?,
                    format_tags(&view.facts, &view.reader, &head.tags)?
                )
                .unwrap();
            }
        }
        Ok(report)
    })?;
    print!("{report}");
    Ok(())
}

fn cmd_history(storage: WikiStorage<'_>, id: String) -> Result<()> {
    let report = storage.view(|view| {
        let entry = mutation_entry(view, &id)?;
        let mut report = String::new();
        writeln!(report, "# History: {}", entry_label(&entry)).unwrap();
        for (index, revision) in wiki_model::entry_history(&view.facts, &entry)
            .iter()
            .enumerate()
        {
            writeln!(
                report,
                "v{}  {:x}  {}  parents=[{}]{}",
                index + 1,
                revision.id,
                revision_title(&view.reader, revision)?,
                revision
                    .supersedes
                    .iter()
                    .map(|id| format!("{id:x}"))
                    .collect::<Vec<_>>()
                    .join(","),
                if entry.frontier.iter().any(|head| head.id == revision.id) {
                    "  [head]"
                } else {
                    ""
                }
            )
            .unwrap();
        }
        Ok(report)
    })?;
    print!("{report}");
    Ok(())
}

fn cmd_tag_list(storage: WikiStorage<'_>) -> Result<()> {
    let rows = storage.view(|view| {
        let mut counts = HashMap::new();
        for id in wiki_model::revision_ids(&view.facts) {
            for revision in wiki_model::revision_records(&view.facts, id) {
                for tag in &revision.tags {
                    *counts.entry(*tag).or_insert(0usize) += 1;
                }
            }
        }
        let mut rows = Vec::new();
        for (id, handle) in find!(
            (id: Id, handle: schema::TextHandle),
            pattern!(&view.facts, [{ ?id @ metadata::name: ?handle }])
        ) {
            rows.push((
                read_string(&view.reader, handle)?,
                id,
                counts.get(&id).copied().unwrap_or(0),
            ));
        }
        rows.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
        Ok(rows)
    })?;
    for (name, id, count) in rows {
        println!("{id:x}  {name}  ({count})");
    }
    Ok(())
}

fn cmd_tag_mint(storage: WikiStorage<'_>, name: String) -> Result<()> {
    let ids = storage.view(|view| tag_ids_named(&view.facts, &view.reader, &name))?;
    if let Some(id) = ids.first() {
        println!("{id:x}  {}", name.trim().to_ascii_lowercase());
        return Ok(());
    }
    let (fragment, id, normalized) = wiki_model::tag_record(&name)?;
    storage.publish(fragment)?;
    println!("{id:x}  {normalized}");
    Ok(())
}

fn collect_typ_files(path: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_file() {
        output.push(path.to_owned());
        return Ok(());
    }
    for entry in fs::read_dir(path).with_context(|| format!("read {}", path.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_typ_files(&path, output)?;
        } else if path.extension().is_some_and(|ext| ext == "typ") {
            output.push(path);
        }
    }
    Ok(())
}

fn cmd_import(storage: WikiStorage<'_>, path: PathBuf, tags: Vec<String>) -> Result<()> {
    let (view, files_catalog, tags, mut fragment) =
        storage.view_with_scope(FILES_SCOPE_ID, "Files", |view, files| {
            let mut fragment = Fragment::empty();
            let tags = resolve_tags(&view.facts, &view.reader, &tags, &mut fragment)?;
            Ok((view.clone(), files.clone(), tags, fragment))
        })?;
    let mut files = Vec::new();
    collect_typ_files(&path, &mut files)?;
    files.sort();
    for path in files {
        let content =
            fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let content = prepare_content(&content, &view.facts, Some(&files_catalog), true)?;
        let title = content
            .lines()
            .find_map(|line| line.strip_prefix("= "))
            .map(str::to_owned)
            .unwrap_or_else(|| {
                path.file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            });
        let revision = stage_revision(storage, &mut fragment, None, title, content, tags.clone())?;
        println!("{revision:x}  {}", path.display());
    }
    if !fragment.facts().is_empty() {
        storage.publish(fragment)?;
    }
    Ok(())
}

fn cmd_search(storage: WikiStorage<'_>, query: String, context: bool, all: bool) -> Result<()> {
    let needle = query.to_ascii_lowercase();
    let report = storage.view(|view| {
        let mut entries = wiki_model::entries(&view.facts, &view.observed);
        if !all {
            entries.retain(|entry| {
                !entry
                    .frontier
                    .iter()
                    .all(|revision| revision.tags.contains(&schema::TAG_ARCHIVED_ID))
            });
        }
        let mut report = String::new();
        for entry in entries {
            for head in &entry.frontier {
                let title = revision_title(&view.reader, head)?;
                let content_text = revision_content(&view.reader, head)?;
                if title.to_ascii_lowercase().contains(&needle)
                    || content_text.to_ascii_lowercase().contains(&needle)
                {
                    writeln!(
                        report,
                        "{:x}  {title}{}",
                        head.id,
                        if entry.frontier.len() > 1 {
                            "  [fork]"
                        } else {
                            ""
                        }
                    )
                    .unwrap();
                    if context {
                        for line in content_text
                            .lines()
                            .filter(|line| line.to_ascii_lowercase().contains(&needle))
                        {
                            writeln!(report, "    {}", line.trim()).unwrap();
                        }
                    }
                }
            }
        }
        Ok(report)
    })?;
    print!("{report}");
    Ok(())
}

/// Report what is actually wrong, which is narrower than what is dangling.
///
/// Until 2026-08-27 every unresolved target counted as a BROKEN_LINK, which
/// made a corpus that links liberally -- a link to a page nobody has written
/// yet marks work worth doing -- report thousands of defects it does not have.
/// Only a citation into an entry whose every current state is archived is
/// breakage; a legacy anchor and an unwritten target are reported separately
/// and counted as neither. `wiki links` is the full classified report.
fn cmd_check(storage: WikiStorage<'_>, compile: bool) -> Result<()> {
    let (summary, diagnostics, issues) = storage.view(|view| {
        let model = FrontierModel::load(&view.reader, &view.facts, &view.observed)?;
        let mut diagnostics = String::new();
        let mut issues = 0usize;
        let mut legacy = 0usize;
        let mut unwritten = 0usize;
        let mut archived = 0usize;
        let entries = wiki_model::entries(&view.facts, &view.observed);
        for entry in &entries {
            // An archived page citing an archived page is not actionable, and
            // scoping links to the LIVE frontier is what keeps this command and
            // `wiki links` from reporting two different numbers for one corpus.
            // Typst still compiles every entry: bad markup is bad archived too.
            let live = entry
                .frontier
                .iter()
                .any(|head| !head.tags.contains(&schema::TAG_ARCHIVED_ID));
            if !live {
                archived += 1;
            }
            for head in &entry.frontier {
                let content = revision_content(&view.reader, head)?;
                for raw in extract_link_targets(&content).into_iter().filter(|_| live) {
                    let id = Id::from_hex(&raw).expect("extractor returns full ids");
                    match model.classify(id) {
                        LinkClass::Live(_) | LinkClass::Ambiguous(_) => {}
                        LinkClass::Retired(target) => {
                            writeln!(
                                diagnostics,
                                "BROKEN_LINK  {:x}  wiki:{raw}  -> archived entry wiki:{:x}",
                                head.id, model.entries[target].label
                            )
                            .unwrap();
                            issues += 1;
                        }
                        LinkClass::Legacy { .. } => {
                            writeln!(diagnostics, "LEGACY_LINK  {:x}  wiki:{raw}", head.id)
                                .unwrap();
                            legacy += 1;
                        }
                        LinkClass::Unwritten(_) => unwritten += 1,
                    }
                }
                if compile {
                    if let Err(error) = validate_typst(&content) {
                        writeln!(diagnostics, "TYPST_ERROR  {:x}  {error}", head.id).unwrap();
                        issues += 1;
                    }
                }
            }
        }
        let entries = entries.len();
        let summary = format!(
            "Checked {} live entries ({archived} archived, links not scanned), \
         {issues} issues ({legacy} legacy anchor, {unwritten} unwritten target)",
            entries - archived
        );
        Ok((summary, diagnostics, issues))
    })?;
    eprint!("{diagnostics}");
    println!("{summary}");
    if issues == 0 {
        println!("All clear!");
    }
    Ok(())
}

enum ReferenceLineResolution {
    AlreadyFull,
    Expanded(String),
}

fn resolve_reference_line(
    line: &str,
    resolver: ReferenceResolver<'_, FactArchive>,
) -> Result<ReferenceLineResolution> {
    let (scheme, rest) = line
        .split_once(':')
        .ok_or_else(|| anyhow!("no scheme:selector format"))?;
    let expanded = resolver.expand(scheme, rest)?;
    let canonical = format!("{scheme}:{expanded}");
    if canonical == line {
        Ok(ReferenceLineResolution::AlreadyFull)
    } else {
        Ok(ReferenceLineResolution::Expanded(canonical))
    }
}

fn cmd_fix_truncated(storage: WikiStorage<'_>, input: String) -> Result<()> {
    let input = faculties::text_arg(&input, "input")?;
    let (view, files) = storage.view_with_scope(FILES_SCOPE_ID, "Files", |view, files| {
        Ok((view.clone(), files.clone()))
    })?;
    let resolver = ReferenceResolver {
        wiki: &view.facts,
        files: Some(&files),
    };
    for line in input.lines().map(str::trim).filter(|line| !line.is_empty()) {
        match resolve_reference_line(line, resolver) {
            Ok(ReferenceLineResolution::AlreadyFull) => {}
            Ok(ReferenceLineResolution::Expanded(value)) => println!("{line}\t{value}"),
            Err(error) => eprintln!("FAILED: {line} — {error}"),
        }
    }
    Ok(())
}

fn cmd_lint(storage: WikiStorage<'_>, fix: bool, check: bool) -> Result<()> {
    let (report, changed, revisions) =
        storage.view_with_scope(FILES_SCOPE_ID, "Files", |view, files| {
            let resolver = ReferenceResolver {
                wiki: &view.facts,
                files: Some(files),
            };
            let mut report = String::new();
            let mut revisions = Vec::new();
            let mut changed = 0usize;
            for entry in wiki_model::entries(&view.facts, &view.observed) {
                for head in &entry.frontier {
                    let content = revision_content(&view.reader, head)?;
                    let revised = lint_fix(&content, resolver);
                    if revised == content {
                        continue;
                    }
                    changed += 1;
                    if !check {
                        writeln!(
                            report,
                            "would fix {:x} ({})",
                            head.id,
                            revision_title(&view.reader, head)?
                        )
                        .unwrap();
                    }
                    if fix {
                        if entry.frontier.len() != 1 {
                            bail!(
                        "cannot lint-fix forked entry {} without an explicit content resolution",
                        entry_label(&entry)
                    );
                        }
                        let title = revision_title(&view.reader, head)?;
                        let tags = head.tags.iter().copied().collect();
                        revisions.push((entry.clone(), title, revised, tags));
                        break;
                    }
                }
            }
            Ok((report, changed, revisions))
        })?;
    let mut fragment = Fragment::empty();
    for (entry, title, content, tags) in revisions {
        stage_revision(storage, &mut fragment, Some(&entry), title, content, tags)?;
    }
    if fix && !fragment.facts().is_empty() {
        storage.publish(fragment)?;
    }
    print!("{report}");
    println!("{changed} revision(s) need lint fixes");
    if check && changed > 0 {
        bail!("lint check failed")
    }
    Ok(())
}

fn cmd_batch_export(storage: WikiStorage<'_>, dir: PathBuf) -> Result<()> {
    let exports = storage.view(|view| {
        let mut exports = Vec::new();
        for entry in wiki_model::entries(&view.facts, &view.observed) {
            for head in &entry.frontier {
                exports.push((head.id, revision_content(&view.reader, head)?));
            }
        }
        Ok(exports)
    })?;
    fs::create_dir_all(&dir)?;
    for (id, content) in exports {
        fs::write(dir.join(format!("{id:x}.typ")), content)?;
    }
    Ok(())
}

fn cmd_batch_import(storage: WikiStorage<'_>, dir: PathBuf) -> Result<()> {
    let mut imports = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().is_none_or(|ext| ext != "typ") {
            continue;
        }
        let raw = path.file_stem().unwrap_or_default().to_string_lossy();
        let revision_id = Id::from_hex(&raw)
            .ok_or_else(|| anyhow!("invalid revision filename {}", path.display()))?;
        imports.push((revision_id, fs::read_to_string(&path)?));
    }
    let revisions = storage.view(|view| {
        let mut revisions = Vec::new();
        for (revision_id, content) in &imports {
            let revision_id = *revision_id;
            let entry = wiki_model::entry(&view.facts, &view.observed, revision_id)
                .ok_or_else(|| anyhow!("unknown revision {revision_id:x}"))?;
            if entry.frontier.len() != 1 || entry.frontier[0].id != revision_id {
                bail!("stale batch file {revision_id:x}: entry frontier changed");
            }
            let head = &entry.frontier[0];
            if content == &revision_content(&view.reader, head)? {
                continue;
            }
            revisions.push((
                entry.clone(),
                revision_title(&view.reader, head)?,
                content.clone(),
                head.tags.iter().copied().collect(),
            ));
        }
        Ok(revisions)
    })?;
    let mut fragment = Fragment::empty();
    for (entry, title, content, tags) in revisions {
        stage_revision(storage, &mut fragment, Some(&entry), title, content, tags)?;
    }
    if !fragment.facts().is_empty() {
        storage.publish(fragment)?;
    }
    Ok(())
}

#[cfg(feature = "local-embed")]
fn l2_normalize(mut values: Vec<f32>) -> Vec<f32> {
    let norm = values.iter().map(|value| value * value).sum::<f32>().sqrt();
    if norm > 0.0 {
        for value in &mut values {
            *value /= norm;
        }
    }
    values
}

#[cfg(feature = "local-embed")]
fn cmd_embed(storage: WikiStorage<'_>) -> Result<()> {
    let documents = storage.view_with_scope(
        EMBEDDINGS_SCOPE_ID,
        "Embeddings",
        |view, embedding_facts| {
            let existing: BTreeSet<Id> = find!(
                revision: Id,
                pattern!(embedding_facts, [{ ?revision @ embeddings::attr::embedding: _?handle }])
            )
            .collect();
            let mut documents = Vec::new();
            for entry in wiki_model::entries(&view.facts, &view.observed)
                .into_iter()
                .filter(|entry| {
                    !entry
                        .frontier
                        .iter()
                        .all(|revision| revision.tags.contains(&schema::TAG_ARCHIVED_ID))
                })
            {
                for head in &entry.frontier {
                    if existing.contains(&head.id) {
                        continue;
                    }
                    documents.push((head.id, revision_content(&view.reader, head)?));
                }
            }
            Ok(documents)
        },
    )?;
    // Blocking model loading/inference runs outside both Tokio and retries.
    let embedder = faculties::nomic::load_text_embedder()?;
    let mut fragment = Fragment::empty();
    for (revision, content) in documents {
        let vector = l2_normalize(embedder.embed_document(&content)?);
        let handle = fragment.put::<Embedding768, _>(vector);
        fragment +=
            entity! { ExclusiveId::force_ref(&revision) @ embeddings::attr::embedding: handle };
    }
    if fragment.facts().is_empty() {
        println!("all current revisions already embedded");
    } else {
        storage.publish_scope(EMBEDDINGS_SCOPE_ID, fragment)?;
    }
    Ok(())
}

#[cfg(not(feature = "local-embed"))]
fn cmd_embed(_storage: WikiStorage<'_>) -> Result<()> {
    bail!("`wiki embed` needs --features local-embed")
}

#[cfg(feature = "local-embed")]
fn cmd_similar(storage: WikiStorage<'_>, query: String) -> Result<()> {
    let embedder = faculties::nomic::load_text_embedder()?;
    let query = l2_normalize(embedder.embed_query(&query)?);
    let report = storage.view_with_scope(
        EMBEDDINGS_SCOPE_ID,
        "Embeddings",
        |view, embedding_facts| {
            let current: BTreeSet<Id> = wiki_model::entries(&view.facts, &view.observed)
                .into_iter()
                .filter(|entry| {
                    !entry
                        .frontier
                        .iter()
                        .all(|revision| revision.tags.contains(&schema::TAG_ARCHIVED_ID))
                })
                .flat_map(|entry| entry.frontier.into_iter().map(|head| head.id))
                .collect();
            let mut pairs = Vec::new();
            for (revision, handle) in find!(
                (revision: Id, handle: Inline<inlineencodings::Handle<Embedding768>>),
                pattern!(embedding_facts, [{ ?revision @ embeddings::attr::embedding: ?handle }])
            ) {
                if !current.contains(&revision) {
                    continue;
                }
                let vector: anybytes::View<[f32]> = view.reader.get(handle)?;
                pairs.push((revision, vector.as_ref().to_vec()));
            }
            let mut report = String::new();
            for (score, revision) in embeddings::nearest(&pairs, &query, 0.0)?
                .into_iter()
                .take(10)
            {
                let title = wiki_model::revision_records(&view.facts, revision)
                    .first()
                    .map(|row| revision_title(&view.reader, row))
                    .transpose()?
                    .unwrap_or_default();
                writeln!(report, "{score:6.3}  {revision:x}  {title}").unwrap();
            }
            Ok(report)
        },
    )?;
    print!("{report}");
    Ok(())
}

#[cfg(not(feature = "local-embed"))]
fn cmd_similar(_storage: WikiStorage<'_>, _query: String) -> Result<()> {
    bail!("`wiki similar` needs --features local-embed")
}

mod typst_validate {
    use typst::diag::FileResult;
    use typst::foundations::{Bytes, Datetime};
    use typst::layout::PagedDocument;
    use typst::syntax::{FileId, Source, VirtualPath};
    use typst::text::{Font, FontBook};
    use typst::utils::LazyHash;
    use typst::{Library, LibraryExt, World};

    pub struct ValidateWorld {
        library: LazyHash<Library>,
        book: LazyHash<FontBook>,
        main_id: FileId,
        source: Source,
    }

    impl ValidateWorld {
        pub fn new(content: &str) -> Self {
            let main_id = FileId::new(None, VirtualPath::new("main.typ"));
            Self {
                library: LazyHash::new(Library::default()),
                book: LazyHash::new(FontBook::new()),
                main_id,
                source: Source::new(main_id, content.to_owned()),
            }
        }
        pub fn validate(&self) -> Result<(), Vec<String>> {
            match typst::compile::<PagedDocument>(self).output {
                Ok(_) => Ok(()),
                Err(errors) => {
                    let errors: Vec<String> = errors
                        .iter()
                        .filter(|error| !error.message.contains("no font"))
                        .map(|error| error.message.to_string())
                        .collect();
                    if errors.is_empty() {
                        Ok(())
                    } else {
                        Err(errors)
                    }
                }
            }
        }
    }
    impl World for ValidateWorld {
        fn library(&self) -> &LazyHash<Library> {
            &self.library
        }
        fn book(&self) -> &LazyHash<FontBook> {
            &self.book
        }
        fn main(&self) -> FileId {
            self.main_id
        }
        fn source(&self, id: FileId) -> FileResult<Source> {
            if id == self.main_id {
                Ok(self.source.clone())
            } else {
                Err(typst::diag::FileError::NotFound(
                    id.vpath().as_rootless_path().into(),
                ))
            }
        }
        fn file(&self, id: FileId) -> FileResult<Bytes> {
            Err(typst::diag::FileError::NotFound(
                id.vpath().as_rootless_path().into(),
            ))
        }
        fn font(&self, _index: usize) -> Option<Font> {
            None
        }
        fn today(&self, _offset: Option<i64>) -> Option<Datetime> {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anybytes::Bytes;
    use std::fs::File;
    use triblespace::core::blob::MemoryBlobStoreSnapshot;
    use triblespace::core::repo::{BlobStoreList, MissingBlob, WantRead};

    struct Fixture {
        _directory: tempfile::TempDir,
        pile: PathBuf,
        key: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            for scope in [schema::DEFAULT_SCOPE_ID, FILES_SCOPE_ID] {
                std::env::remove_var(faculties::collection_names::override_env_name(scope));
            }
            let directory = tempfile::tempdir().unwrap();
            let pile = directory.path().join("wiki.pile");
            let key = directory.path().join("wiki.key");
            File::create(&pile).unwrap();
            faculties::storage::initialize_signer(&pile, Some(&key)).unwrap();
            Self {
                _directory: directory,
                pile,
                key,
            }
        }

        fn storage(&self) -> WikiStorage<'_> {
            WikiStorage {
                pile: &self.pile,
                key: Some(&self.key),
            }
        }
    }

    /// Model the exact requested bytes arriving from a concurrent replicator
    /// between a resident miss and the live store's acquisition attempt.
    /// Returning the original miss still exercises the production retry loop.
    fn supply_selected_blob(
        fixture: &Fixture,
        remote: &MemoryBlobStoreSnapshot,
        error: &anyhow::Error,
    ) -> Inline<inlineencodings::Handle<blobencodings::UnknownBlob>> {
        let missing = error
            .chain()
            .find_map(|error| error.downcast_ref::<MissingBlob>())
            .expect("the selected payload must identify its exact missing handle");
        let bytes: Bytes = remote.get(missing.handle).unwrap();
        let mut arrival = faculties::storage::open_pile_strict(&fixture.pile).unwrap();
        assert_eq!(
            arrival.put::<blobencodings::UnknownBlob, _>(bytes).unwrap(),
            missing.handle
        );
        arrival.close().unwrap();
        missing.handle
    }

    #[test]
    fn sparse_payload_retry_keeps_selected_revision_and_publishes_only_after_preparation() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let mut genesis = Fragment::empty();
        let (tag_fragment, tag, _) = wiki_model::tag_record("selected-tag").unwrap();
        genesis += tag_fragment;
        let root = stage_revision(
            storage,
            &mut genesis,
            None,
            "selected title".to_owned(),
            "selected original body".to_owned(),
            BTreeSet::from([tag]),
        )
        .unwrap();
        let unrelated = stage_revision(
            storage,
            &mut genesis,
            None,
            "unrelated title".to_owned(),
            "unrelated body stays cold".to_owned(),
            BTreeSet::new(),
        )
        .unwrap();
        let selected = wiki_model::revision_records(genesis.facts(), root).remove(0);
        let cold = wiki_model::revision_records(genesis.facts(), unrelated).remove(0);
        let mut remote = genesis.blobs().clone();
        let remote = remote.snapshot().unwrap();
        genesis.blobs_mut().keep([]);
        storage.publish(genesis).unwrap();

        // This later revision is staged before the read but arrives only on
        // its first payload miss. The selected frontier must not follow it.
        let (_, author) = storage.author_fragment().unwrap();
        let (arrival, later) = wiki_model::revision_record(RevisionDraft {
            title: "later title".to_owned(),
            content: "later body".to_owned(),
            tags: BTreeSet::from([tag]),
            predecessors: BTreeSet::from([root]),
            author,
            authored_at: point(2.0),
        })
        .unwrap();
        let mut arrival = Some(arrival);
        let mut requested = Vec::new();
        let mut original = None::<PileSnapshot>;
        let (report, entry, title, content) = storage
            .view(|view| {
                let original = original.get_or_insert_with(|| view.reader.clone());
                assert_eq!(view.reader.instant(), original.instant());
                let entry = mutation_entry(view, &format!("{root:x}"))?;
                assert_eq!(
                    entry
                        .frontier
                        .iter()
                        .map(|head| head.id)
                        .collect::<Vec<_>>(),
                    [root]
                );
                let head = &entry.frontier[0];
                let prepared = (|| {
                    Ok((
                        render_revision(&view.facts, &view.reader, head)?,
                        entry.clone(),
                        revision_title(&view.reader, head)?,
                        revision_content(&view.reader, head)?,
                    ))
                })();
                if let Err(error) = &prepared {
                    requested.push(supply_selected_blob(&fixture, &remote, error));
                    if let Some(arrival) = arrival.take() {
                        let signer = load_signer(&fixture.pile, Some(&fixture.key))?;
                        let mut writer = faculties::storage::open_pile_strict(&fixture.pile)?;
                        let source = open_configured(
                            &mut writer,
                            schema::DEFAULT_SCOPE_ID,
                            signer.verifying_key(),
                        )?;
                        writer.commit(source, &signer, arrival)?;
                        writer.close()?;
                    }
                }
                prepared
            })
            .unwrap();
        assert!(report.contains("selected original body"));
        assert!(!report.contains("later body"));
        assert_eq!(
            requested.len(),
            3,
            "only the selected title, tag name, and body are read"
        );
        let original = original.unwrap();
        for handle in &requested {
            assert!(!original.contains_blob(*handle).unwrap());
        }
        assert!(requested.contains(&selected.title.transmute()));
        assert!(requested.contains(&selected.content.transmute()));
        assert!(!requested.contains(&cold.title.transmute()));
        assert!(!requested.contains(&cold.content.transmute()));

        // Authored time and publication happen once, after every retry. The
        // concurrent revision remains a separate visible frontier branch.
        let mut edit = Fragment::empty();
        let written = stage_revision(
            storage,
            &mut edit,
            Some(&entry),
            title,
            format!("{content}\nprepared once"),
            BTreeSet::from([tag]),
        )
        .unwrap();
        storage.publish(edit).unwrap();
        storage
            .view(|view| {
                let entry = mutation_entry(view, &format!("{root:x}"))?;
                assert_eq!(
                    entry
                        .frontier
                        .iter()
                        .map(|head| head.id)
                        .collect::<BTreeSet<_>>(),
                    BTreeSet::from([later, written])
                );
                let written = wiki_model::revision_records(&view.facts, written).remove(0);
                assert_eq!(
                    written.authorships.len(),
                    1,
                    "retrying text must not repeat authored observations"
                );
                assert!(!view.reader.contains_blob(cold.title).unwrap());
                assert!(!view.reader.contains_blob(cold.content).unwrap());
                assert_eq!(view.reader.wants().unwrap().count(), 0);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn a_cold_tag_name_is_not_absence_and_mint_does_not_republish_it() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let (mut tag, expected, _) = wiki_model::tag_record("known-cold-tag").unwrap();
        let mut remote = tag.blobs().clone();
        let remote = remote.snapshot().unwrap();
        tag.blobs_mut().keep([]);
        storage.publish(tag).unwrap();
        let mut requested = Vec::new();
        let ids = storage
            .view(|view| {
                let result = tag_ids_named(&view.facts, &view.reader, "known-cold-tag");
                if let Err(error) = &result {
                    requested.push(supply_selected_blob(&fixture, &remote, error));
                }
                result
            })
            .unwrap();
        assert_eq!(ids, BTreeSet::from([expected]));
        assert_eq!(requested.len(), 1);
        let before = fs::read(&fixture.pile).unwrap();
        cmd_tag_mint(storage, "known-cold-tag".to_owned()).unwrap();
        assert_eq!(
            fs::read(&fixture.pile).unwrap(),
            before,
            "an existing cold tag must not be republished"
        );
    }

    #[test]
    fn edit_joins_the_complete_current_frontier() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let mut genesis = Fragment::empty();
        let root = stage_revision(
            storage,
            &mut genesis,
            None,
            "root".to_owned(),
            "body".to_owned(),
            BTreeSet::new(),
        )
        .unwrap();
        storage.publish(genesis).unwrap();

        let current = storage.view(|view| Ok(view.clone())).unwrap();
        let entry = wiki_model::entry(&current.facts, &current.observed, root).unwrap();
        let mut forks = Fragment::empty();
        let left = stage_revision(
            storage,
            &mut forks,
            Some(&entry),
            "left".to_owned(),
            "left".to_owned(),
            BTreeSet::new(),
        )
        .unwrap();
        let right = stage_revision(
            storage,
            &mut forks,
            Some(&entry),
            "right".to_owned(),
            "right".to_owned(),
            BTreeSet::new(),
        )
        .unwrap();
        storage.publish(forks).unwrap();

        cmd_edit(
            storage,
            format!("{left:x}"),
            Some("joined".to_owned()),
            Some("joined".to_owned()),
            Vec::new(),
            true,
        )
        .unwrap();
        let after = storage.view(|view| Ok(view.clone())).unwrap();
        let entry = wiki_model::entry(&after.facts, &after.observed, left).unwrap();
        assert_eq!(entry.frontier.len(), 1);
        assert_eq!(entry.frontier[0].supersedes, BTreeSet::from([left, right]));
    }

    /// Publish `root`, then supersede it, and hand back both ids.
    fn superseded_pair(storage: WikiStorage<'_>) -> (Id, Id) {
        let mut genesis = Fragment::empty();
        let root = stage_revision(
            storage,
            &mut genesis,
            None,
            "page".to_owned(),
            "first draft".to_owned(),
            BTreeSet::new(),
        )
        .unwrap();
        storage.publish(genesis).unwrap();

        cmd_edit(
            storage,
            format!("{root:x}"),
            Some("second draft".to_owned()),
            None,
            Vec::new(),
            true,
        )
        .unwrap();

        let after = storage.view(|view| Ok(view.clone())).unwrap();
        let entry = wiki_model::entry(&after.facts, &after.observed, root).unwrap();
        assert_eq!(entry.frontier.len(), 1);
        (root, entry.frontier[0].id)
    }

    /// The default reading follows the entry: naming a superseded id returns
    /// what that page says NOW, not the text it said when it was cited.
    #[test]
    fn show_follows_a_superseded_id_to_the_frontier_by_default() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let (root, head) = superseded_pair(storage);
        assert_ne!(root, head, "the fixture must actually supersede something");

        let view = storage.view(|view| Ok(view.clone())).unwrap();
        let shown = selector_revisions(&view, root, true).unwrap();
        assert_eq!(
            shown.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![head],
            "a superseded selector must resolve forward to the head"
        );
        assert_eq!(
            revision_content(&view.reader, &shown[0]).unwrap(),
            "second draft"
        );
        cmd_show(storage, format!("{root:x}"), false).unwrap();
    }

    /// `--exact` is the whole escape hatch: it must return the frozen text,
    /// or history becomes unreadable.
    #[test]
    fn exact_pins_the_named_revision() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let (root, head) = superseded_pair(storage);

        let view = storage.view(|view| Ok(view.clone())).unwrap();
        let pinned = selector_revisions(&view, root, false).unwrap();
        assert_eq!(pinned.iter().map(|r| r.id).collect::<Vec<_>>(), vec![root]);
        assert_eq!(
            revision_content(&view.reader, &pinned[0]).unwrap(),
            "first draft"
        );
        cmd_show(storage, format!("{root:x}"), true).unwrap();
        // The head still reads as itself under either policy.
        assert_eq!(
            selector_revisions(&view, head, true)
                .unwrap()
                .iter()
                .map(|r| r.id)
                .collect::<Vec<_>>(),
            vec![head]
        );
    }

    /// Following the entry must not soften the one honest failure: an id that
    /// names nothing still fails, with the same message it always had.
    #[test]
    fn an_id_that_names_nothing_still_fails_loudly() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let (_root, _head) = superseded_pair(storage);
        let view = storage.view(|view| Ok(view.clone())).unwrap();

        let absent = "f40312df406d1bf1bb5c94ec954e490b";
        let error = resolve_prefix(&view.facts, absent).unwrap_err().to_string();
        assert!(error.contains("no Wiki id matches"), "got: {error}");
        assert!(cmd_show(storage, absent.to_owned(), false).is_err());
        assert!(cmd_show(storage, absent.to_owned(), true).is_err());
    }

    /// A forked entry has no single current text. `show` prints EVERY head —
    /// picking one silently is precisely the failure the new default removes —
    /// while `export`, which must emit one document, refuses and names them.
    #[test]
    fn a_forked_frontier_shows_every_head_and_export_refuses() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let mut genesis = Fragment::empty();
        let root = stage_revision(
            storage,
            &mut genesis,
            None,
            "root".to_owned(),
            "body".to_owned(),
            BTreeSet::new(),
        )
        .unwrap();
        storage.publish(genesis).unwrap();

        let current = storage.view(|view| Ok(view.clone())).unwrap();
        let entry = wiki_model::entry(&current.facts, &current.observed, root).unwrap();
        let mut forks = Fragment::empty();
        let left = stage_revision(
            storage,
            &mut forks,
            Some(&entry),
            "left".to_owned(),
            "left".to_owned(),
            BTreeSet::new(),
        )
        .unwrap();
        let right = stage_revision(
            storage,
            &mut forks,
            Some(&entry),
            "right".to_owned(),
            "right".to_owned(),
            BTreeSet::new(),
        )
        .unwrap();
        storage.publish(forks).unwrap();

        let view = storage.view(|view| Ok(view.clone())).unwrap();
        let heads: BTreeSet<Id> = selector_revisions(&view, root, true)
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(heads, BTreeSet::from([left, right]));
        cmd_show(storage, format!("{root:x}"), false).unwrap();

        let error = cmd_export(storage, format!("{root:x}"), false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("fork"), "got: {error}");
        assert!(error.contains(&format!("{left:x}")), "got: {error}");
        // Naming one head exactly is how a caller resolves the ambiguity.
        cmd_export(storage, format!("{left:x}"), true).unwrap();
    }

    #[test]
    fn unanchored_native_revision_is_a_cli_selector() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let files = storage
            .view_with_scope(FILES_SCOPE_ID, "Files", |_, files| Ok(files.clone()))
            .unwrap();
        assert!(find!(
            id: Id,
            pattern!(&files, [{ ?id @ metadata::tag: _?kind }])
        )
        .next()
        .is_none());
        let mut fragment = Fragment::empty();
        let revision = stage_revision(
            storage,
            &mut fragment,
            None,
            "native".to_owned(),
            "body".to_owned(),
            BTreeSet::new(),
        )
        .unwrap();
        storage.publish(fragment).unwrap();
        let after = storage.view(|view| Ok(view.clone())).unwrap();
        assert_eq!(
            resolve_prefix(&after.facts, &format!("{revision:x}")).unwrap(),
            revision
        );
        let entry = wiki_model::entry(&after.facts, &after.observed, revision).unwrap();
        assert_eq!(entry.roots, vec![revision]);
    }

    #[test]
    fn lint_preserves_typed_link_while_expanding_the_selector() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let mut fragment = Fragment::empty();
        let revision = stage_revision(
            storage,
            &mut fragment,
            None,
            "target".to_owned(),
            "body".to_owned(),
            BTreeSet::new(),
        )
        .unwrap();
        storage.publish(fragment).unwrap();
        let after = storage.view(|view| Ok(view.clone())).unwrap();
        let short = &format!("{revision:x}")[..8];
        let fixed = lint_fix(
            &format!("[review](wiki:reviews:{short})"),
            ReferenceResolver {
                wiki: &after.facts,
                files: None,
            },
        );
        assert_eq!(
            fixed,
            format!("#link(\"wiki:reviews:{revision:x}\")[review]")
        );
    }

    /// A citation belongs to the revision that made it, not to the page.
    ///
    /// A1 cites X and its successor A2 does not. Incoming links on X must name
    /// A1 — that citation was really written — and must NOT name A2, whose
    /// text says nothing about X. Naming the entry would have to pick one of
    /// those two answers and would be wrong either way.
    #[test]
    fn backlinks_name_the_citing_revision_not_its_successor() {
        let fixture = Fixture::new();
        let storage = fixture.storage();

        let mut genesis = Fragment::empty();
        let target = stage_revision(
            storage,
            &mut genesis,
            None,
            "target".to_owned(),
            "body".to_owned(),
            BTreeSet::new(),
        )
        .unwrap();
        let citing = stage_revision(
            storage,
            &mut genesis,
            None,
            "source".to_owned(),
            format!("cites #link(\"wiki:{target:x}\")[target]"),
            BTreeSet::new(),
        )
        .unwrap();
        storage.publish(genesis).unwrap();

        // A2: same page, citation removed.
        let current = storage.view(|view| Ok(view.clone())).unwrap();
        let source_entry = wiki_model::entry(&current.facts, &current.observed, citing).unwrap();
        let mut edit = Fragment::empty();
        let dropped = stage_revision(
            storage,
            &mut edit,
            Some(&source_entry),
            "source".to_owned(),
            "no citation any more".to_owned(),
            BTreeSet::new(),
        )
        .unwrap();
        storage.publish(edit).unwrap();

        let after = storage.view(|view| Ok(view.clone())).unwrap();
        // `dropped` really is the page's current text, so an entry-scoped
        // answer would have had a live entry to name.
        let source_entry = wiki_model::entry(&after.facts, &after.observed, citing).unwrap();
        assert_eq!(
            source_entry
                .frontier
                .iter()
                .map(|head| head.id)
                .collect::<Vec<_>>(),
            vec![dropped]
        );

        let target_entry = wiki_model::entry(&after.facts, &after.observed, target).unwrap();
        let incoming = incoming_revisions(&after, &target_entry).unwrap();
        assert!(
            incoming.contains(&citing),
            "the revision that wrote the citation must be listed"
        );
        assert!(
            !incoming.contains(&dropped),
            "a revision whose text does not cite the target must not be listed"
        );
    }

    /// The same asymmetry, seen through the `--with-backlink-tag` index: the
    /// citing revision's own tags describe the citation, not its successor's.
    #[test]
    fn backlink_summaries_carry_the_citing_revision_tags_only() {
        let fixture = Fixture::new();
        let storage = fixture.storage();

        let mut genesis = Fragment::empty();
        let target = stage_revision(
            storage,
            &mut genesis,
            None,
            "target".to_owned(),
            "body".to_owned(),
            BTreeSet::new(),
        )
        .unwrap();
        let (citing_tag_fragment, citing_tag, _) = wiki_model::tag_record("citing").unwrap();
        let (later_tag_fragment, later_tag, _) = wiki_model::tag_record("later").unwrap();
        genesis += citing_tag_fragment;
        genesis += later_tag_fragment;
        let citing = stage_revision(
            storage,
            &mut genesis,
            None,
            "source".to_owned(),
            format!("cites #link(\"wiki:{target:x}\")[target]"),
            BTreeSet::from([citing_tag]),
        )
        .unwrap();
        storage.publish(genesis).unwrap();

        let current = storage.view(|view| Ok(view.clone())).unwrap();
        let source_entry = wiki_model::entry(&current.facts, &current.observed, citing).unwrap();
        let mut edit = Fragment::empty();
        stage_revision(
            storage,
            &mut edit,
            Some(&source_entry),
            "source".to_owned(),
            "no citation any more".to_owned(),
            BTreeSet::from([later_tag]),
        )
        .unwrap();
        storage.publish(edit).unwrap();

        let after = storage.view(|view| Ok(view.clone())).unwrap();
        let summaries = backlink_summaries(&after.reader, &after.facts).unwrap();
        assert_eq!(
            summaries.get(&target).unwrap().tags,
            BTreeSet::from([citing_tag])
        );
    }

    #[test]
    fn backlink_summaries_index_typed_links_and_source_tags() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let mut fragment = Fragment::empty();
        let target = stage_revision(
            storage,
            &mut fragment,
            None,
            "target".to_owned(),
            "body".to_owned(),
            BTreeSet::new(),
        )
        .unwrap();
        let (tag_fragment, source_tag, _) = wiki_model::tag_record("source").unwrap();
        fragment += tag_fragment;
        stage_revision(
            storage,
            &mut fragment,
            None,
            "source".to_owned(),
            format!("#link(\"wiki:Reviews:{target:x}\")[review]"),
            BTreeSet::from([source_tag]),
        )
        .unwrap();
        storage.publish(fragment).unwrap();

        let after = storage.view(|view| Ok(view.clone())).unwrap();
        let summaries = backlink_summaries(&after.reader, &after.facts).unwrap();
        let incoming = summaries.get(&target).unwrap();
        assert_eq!(incoming.tags, BTreeSet::from([source_tag]));
        assert_eq!(incoming.types, BTreeSet::from(["reviews".to_owned()]));
    }

    use triblespace::core::metadata;

    fn point(seconds: f64) -> Inline<inlineencodings::NsTAIInterval> {
        let epoch = Epoch::from_tai_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    /// Anchor A with two versions, v2 current. Returns (facts, A, v1, v2).
    fn legacy_anchor_pair() -> (Fragment, Id, Id, Id) {
        let anchor = genid().id;
        let mut fragment = Fragment::empty();
        let title: schema::TextHandle = fragment.put("T".to_owned());
        let older: schema::TextHandle = fragment.put("first text".to_owned());
        let newer: schema::TextHandle = fragment.put("second text".to_owned());
        let v1 = genid().id;
        let v2 = genid().id;
        fragment += entity! { ExclusiveId::force_ref(&v1) @
            metadata::tag: &schema::KIND_VERSION_ID,
            schema::attrs::fragment: anchor,
            schema::attrs::title: title,
            schema::attrs::content: older,
            metadata::created_at: point(1.0),
        };
        fragment += entity! { ExclusiveId::force_ref(&v2) @
            metadata::tag: &schema::KIND_VERSION_ID,
            schema::attrs::fragment: anchor,
            schema::attrs::title: title,
            schema::attrs::content: newer,
            metadata::created_at: point(2.0),
            metadata::supersedes: v1,
        };
        (fragment, anchor, v1, v2)
    }

    /// A legacy anchor resolves to nothing at all.
    ///
    /// `wiki lint` rewrote every anchor reference in the corpus to the
    /// anchor's then-current head before this lookup was removed, so what
    /// remains is history: superseded revisions whose text still names an
    /// anchor. Those must be left EXACTLY as written — an unresolvable
    /// reference is a fact about the past, and mangling it would be worse than
    /// leaving it broken. `wiki check` is what reports it.
    #[test]
    fn a_legacy_anchor_is_not_a_selector_and_is_left_untouched() {
        let (fragment, anchor, v1, _v2) = legacy_anchor_pair();
        let resolver = ReferenceResolver {
            wiki: fragment.facts(),
            files: None,
        };
        assert!(
            !wiki_model::revision_records(fragment.facts(), v1).is_empty(),
            "the fixture's legacy versions must load, or this proves nothing"
        );
        let error = resolve_prefix(fragment.facts(), &format!("{anchor:x}"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("no Wiki id matches"), "got: {error}");

        for content in [
            format!("see #link(\"wiki:{anchor:x}\")[the page]\n"),
            format!("#link(\"wiki:{anchor:x}\")[wiki:{anchor:x}]\n"),
            format!("context: wiki:{anchor:x} says so\n"),
        ] {
            assert_eq!(lint_fix(&content, resolver), content);
        }
    }

    /// A citation is already pinned, so the pass must not touch it — including
    /// a citation of a SUPERSEDED revision, which names what its author read.
    #[test]
    fn lint_leaves_revision_citations_byte_unchanged() {
        let (fragment, _anchor, v1, v2) = legacy_anchor_pair();
        let resolver = ReferenceResolver {
            wiki: fragment.facts(),
            files: None,
        };
        for target in [v1, v2] {
            let content = format!("cites #link(\"wiki:{target:x}\")[pinned]\n");
            assert_eq!(lint_fix(&content, resolver), content);
        }
        // A truncated prefix of a revision still resolves, and completing it
        // is a fixpoint.
        let once = lint_fix(&format!("wiki:{}", &format!("{v2:x}")[..12]), resolver);
        assert_eq!(once, format!("wiki:{v2:x}"));
        assert_eq!(lint_fix(&once, resolver), once);
    }

    /// End to end: `wiki lint --fix` mints a SUCCESSOR carrying the corrected
    /// reference and leaves the revision it found exactly as it found it.
    #[test]
    fn lint_fix_mints_a_successor_and_never_edits_the_original() {
        let fixture = Fixture::new();
        let storage = fixture.storage();

        let mut genesis = Fragment::empty();
        let target = stage_revision(
            storage,
            &mut genesis,
            None,
            "target".to_owned(),
            "body".to_owned(),
            BTreeSet::new(),
        )
        .unwrap();
        storage.publish(genesis).unwrap();

        let truncated = format!("{target:x}")[..12].to_owned();
        let mut fragment = Fragment::empty();
        let citing = stage_revision(
            storage,
            &mut fragment,
            None,
            "source".to_owned(),
            format!("see #link(\"wiki:{truncated}\")[the page]"),
            BTreeSet::new(),
        )
        .unwrap();
        storage.publish(fragment).unwrap();

        cmd_lint(storage, true, false).unwrap();

        let after = storage.view(|view| Ok(view.clone())).unwrap();
        let original = wiki_model::revision_records(&after.facts, citing)
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(
            read_string(&after.reader, original.content).unwrap(),
            format!("see #link(\"wiki:{truncated}\")[the page]"),
            "the original revision is content-addressed and must be untouched"
        );
        let entry = wiki_model::entry(&after.facts, &after.observed, citing).unwrap();
        assert_eq!(entry.frontier.len(), 1);
        let head = &entry.frontier[0];
        assert_ne!(head.id, citing, "the fix is a successor, not a mutation");
        assert_eq!(head.supersedes, BTreeSet::from([citing]));
        assert_eq!(
            read_string(&after.reader, head.content).unwrap(),
            format!("see #link(\"wiki:{target:x}\")[the page]")
        );
    }

    /// A selector that does not resolve must say WHICH kind of not-resolving.
    ///
    /// Measured need, not a hypothetical: the two wiki ids named by the
    /// standing orphan goals both fail this lookup, and both turn out to be
    /// legacy anchors rather than typos -- which "no Wiki id matches" alone
    /// could never tell anyone.
    #[test]
    fn a_failed_selector_says_whether_it_is_an_anchor_or_nothing() {
        let fixture = Fixture::new();
        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let (author_fragment, _) = wiki_model::author_record(&signer.verifying_key());
        let (legacy, anchor, _v1, _v2) = legacy_anchor_pair();
        let mut pile = faculties::storage::open_pile_strict(&fixture.pile).unwrap();
        let collection = faculties::collection_names::open(
            &mut pile,
            schema::DEFAULT_SCOPE_ID,
            signer.verifying_key(),
        )
        .unwrap();
        pile.commit(collection, &signer, author_fragment + legacy)
            .unwrap();
        pile.close().unwrap();

        let storage = fixture.storage();
        let view = storage.view(|view| Ok(view.clone())).unwrap();

        let anchor_hex = format!("{anchor:x}");
        let reported = explain_selector(
            &view,
            &anchor_hex,
            anyhow!("no Wiki id matches '{anchor_hex}'"),
        )
        .unwrap()
        .to_string();
        assert!(
            reported.contains("LEGACY FRAGMENT ANCHOR"),
            "an anchor must be named as one; got: {reported}"
        );

        let never = "ffffffffffffffffffffffffffffffff";
        let reported = explain_selector(&view, never, anyhow!("no Wiki id matches '{never}'"))
            .unwrap()
            .to_string();
        assert!(
            reported.contains("no fragment has ever had it") && !reported.contains("ANCHOR"),
            "an id no fragment ever had must not be called an anchor; got: {reported}"
        );
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };
    let storage = WikiStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
    };
    match command {
        Command::Create {
            title,
            content,
            tag,
            force,
        } => cmd_create(storage, title, content, tag, force),
        Command::Edit {
            id,
            content,
            title,
            tag,
            force,
        } => cmd_edit(storage, id, content, title, tag, force),
        Command::Show { id, exact } => cmd_show(storage, id, exact),
        Command::Export { id, exact } => cmd_export(storage, id, exact),
        Command::Diff { id, from, to } => cmd_diff(storage, id, from, to),
        Command::Archive { id } => mutate_tags(storage, id, "archived", true),
        Command::Restore { id } => mutate_tags(storage, id, "archived", false),
        Command::Revert { id, to } => cmd_revert(storage, id, to),
        Command::Links { id, top, strict } => cmd_links(storage, id, top, strict),
        Command::List {
            tag,
            with_backlink_tag,
            without_backlink_tag,
            with_backlink_type,
            without_backlink_type,
            all,
        } => cmd_list(
            storage,
            tag,
            with_backlink_tag,
            without_backlink_tag,
            with_backlink_type,
            without_backlink_type,
            all,
        ),
        Command::History { id } => cmd_history(storage, id),
        Command::Tag { command } => match command {
            TagCommand::Add { id, name } => mutate_tags(storage, id, &name, true),
            TagCommand::Remove { id, name } => mutate_tags(storage, id, &name, false),
            TagCommand::List => cmd_tag_list(storage),
            TagCommand::Mint { name } => cmd_tag_mint(storage, name),
        },
        Command::Import { path, tag } => cmd_import(storage, path, tag),
        Command::Search {
            query,
            context,
            all,
        } => cmd_search(storage, query, context, all),
        Command::Embed => cmd_embed(storage),
        Command::Similar { query } => cmd_similar(storage, query),
        Command::Batch {
            action: BatchAction::Export { dir },
        } => cmd_batch_export(storage, dir),
        Command::Batch {
            action: BatchAction::Import { dir },
        } => cmd_batch_import(storage, dir),
        Command::Check { compile } => cmd_check(storage, compile),
        Command::FixTruncated { input } => cmd_fix_truncated(storage, input),
        Command::Lint { fix, check } => cmd_lint(storage, fix, check),
    }
}
