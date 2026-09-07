//! Wiki command-line UX: Clap, host paths, and @file/@- expansion live here.

use super::operations::{ImportDocument, ListOptions, Wiki};
use crate::out::Out;
use anyhow::{anyhow, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use triblespace::prelude::Id;

#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
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

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    if cli.command.is_none() {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }
    crate::cli::with_output("wiki", |out| execute(cli, out))
}

/// Parse explicit CLI arguments. This seam keeps frontend tests off process
/// stdout while preserving the same path/text expansion as the executable.
pub fn execute_from<I, T>(arguments: I, out: &mut Out<'_>) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    execute(Cli::try_parse_from(arguments)?, out)
}

fn revision(out: &mut Out<'_>, id: Id) -> Result<()> {
    out.line(format!("revision {id:x}"))
}
fn tag_change(out: &mut Out<'_>, result: Option<Id>, name: &str, add: bool) -> Result<()> {
    match result {
        Some(id) => revision(out, id),
        None => out.line(format!(
            "already {} #{}",
            if add { "tagged" } else { "untagged" },
            name.trim().to_ascii_lowercase()
        )),
    }
}

fn execute(cli: Cli, out: &mut Out<'_>) -> Result<()> {
    let wiki = Wiki::new(cli.pile, cli.key);
    let Some(command) = cli.command else {
        return Ok(());
    };
    match command {
        Command::Create {
            title,
            content,
            tag,
            force,
        } => {
            let title = crate::text_arg(&title, "title")?;
            let content = crate::text_arg(&content, "content")?;
            revision(out, wiki.create(&title, &content, &tag, force)?)
        }
        Command::Edit {
            id,
            content,
            title,
            tag,
            force,
        } => {
            let title = title
                .map(|value| crate::text_arg(&value, "title"))
                .transpose()?;
            let content = content
                .map(|value| crate::text_arg(&value, "content"))
                .transpose()?;
            revision(
                out,
                wiki.edit(&id, content.as_deref(), title.as_deref(), &tag, force)?,
            )
        }
        Command::Show { id, exact } => out.text(wiki.show(&id, exact)?),
        Command::Export { id, exact } => {
            let export = wiki.export(&id, exact)?;
            let uri = export.uri();
            out.blob(export.bytes, "text/plain; charset=utf-8", uri)
        }
        Command::Diff { id, from, to } => out.text(wiki.diff(&id, from, to)?),
        Command::Archive { id } => tag_change(out, wiki.archive(&id)?, "archived", true),
        Command::Restore { id } => tag_change(out, wiki.restore(&id)?, "archived", false),
        Command::Revert { id, to } => revision(out, wiki.revert(&id, to)?),
        Command::Links { id, top, strict } => wiki.links(id.as_deref(), top, strict, out),
        Command::List {
            tag,
            with_backlink_tag,
            without_backlink_tag,
            with_backlink_type,
            without_backlink_type,
            all,
        } => out.text(wiki.list(&ListOptions {
            tags: tag,
            with_backlink_tag,
            without_backlink_tag,
            with_backlink_type,
            without_backlink_type,
            all,
        })?),
        Command::History { id } => out.text(wiki.history(&id)?),
        Command::Tag { command } => match command {
            TagCommand::Add { id, name } => {
                tag_change(out, wiki.tag(&id, &name, true)?, &name, true)
            }
            TagCommand::Remove { id, name } => {
                tag_change(out, wiki.tag(&id, &name, false)?, &name, false)
            }
            TagCommand::List => wiki.tags(out),
            TagCommand::Mint { name } => out.line(format!(
                "{:x}  {}",
                wiki.mint_tag(&name)?,
                name.trim().to_ascii_lowercase()
            )),
        },
        Command::Import { path, tag } => import(&wiki, &path, &tag, out),
        Command::Search {
            query,
            context,
            all,
        } => out.text(wiki.search(&query, context, all)?),
        Command::Embed => wiki.embed(out),
        Command::Similar { query } => out.text(wiki.similar(&query)?),
        Command::Batch {
            action: BatchAction::Export { dir },
        } => {
            let exports = wiki.export_all()?;
            fs::create_dir_all(&dir)?;
            for (id, content) in exports {
                fs::write(dir.join(format!("{id:x}.typ")), content)?;
            }
            Ok(())
        }
        Command::Batch {
            action: BatchAction::Import { dir },
        } => {
            let mut imports = Vec::new();
            for entry in fs::read_dir(&dir)? {
                let path = entry?.path();
                if path.extension().is_none_or(|ext| ext != "typ") {
                    continue;
                }
                let raw = path.file_stem().unwrap_or_default().to_string_lossy();
                let id = Id::from_hex(&raw)
                    .ok_or_else(|| anyhow!("invalid revision filename {}", path.display()))?;
                imports.push((id, fs::read_to_string(&path)?));
            }
            wiki.import_revisions(imports)
        }
        Command::Check { compile } => wiki.check(compile, out),
        Command::FixTruncated { input } => {
            wiki.fix_truncated(&crate::text_arg(&input, "input")?, out)
        }
        Command::Lint { fix, check } => wiki.lint(fix, check, out),
    }
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

fn import(wiki: &Wiki, path: &Path, tags: &[String], out: &mut Out<'_>) -> Result<()> {
    let mut paths = Vec::new();
    collect_typ_files(path, &mut paths)?;
    paths.sort();
    let documents = paths
        .iter()
        .map(|path| {
            Ok(ImportDocument {
                title: path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                content: fs::read_to_string(path)
                    .with_context(|| format!("read {}", path.display()))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let ids = wiki.import_texts(documents, tags)?;
    for (id, path) in ids.into_iter().zip(paths) {
        out.line(format!("{id:x}  {}", path.display()))?;
    }
    Ok(())
}
