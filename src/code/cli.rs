//! The `code` command.
//!
//! `code` is what JP named this, and it is free on this box. It is also VS
//! Code's CLI on macOS, where the release cohort installs, so the two-second
//! pre-flight before a Mac build is `command -v code`. A collision there is
//! LOUD — an agent launches an editor and it visibly fails — not silent, and the
//! rename would be mechanical: one scope id, one `collection_names` entry, one
//! `src/bin/*.rs`, one module path.

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{CommandFactory, Parser, Subcommand};

use super::index::Tier;
use super::operations::{Code, Filter, IngestOptions, Revision};
use super::render;
use crate::out::Out;

#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "code",
    about = "A source catalogue: what exists, what uses what, and what is defined where"
)]
pub struct Cli {
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
    /// Catalogue one or more git working copies. Re-ingesting an unchanged
    /// tree is a no-op, and two machines ingesting the same commit converge.
    Ingest {
        /// Repository roots. Defaults to the current directory.
        dirs: Vec<PathBuf>,
        /// Read one named revision from git objects instead of the working
        /// tree. An uncommitted tree is catalogued under a content digest.
        #[arg(long)]
        commit: Option<String>,
        /// Report what would be read without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Where a name is DEFINED — or an affirmative ABSENT verdict with the
    /// denominator it is absent from.
    Find {
        name: String,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Which declarations syntactically NAME an identifier. Zero rows is the
    /// answer, not an empty result.
    Uses {
        identifier: String,
        /// Count the units whose `use` paths start with this root instead.
        #[arg(long)]
        imports: bool,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Everything the catalogue holds about one item.
    Show {
        /// An item id prefix, or a declaration name.
        selector: String,
        /// Print the declaration's source lines.
        #[arg(long)]
        source: bool,
    },
    /// Code that exists in more than one place.
    Dup {
        /// Ignore duplicates shorter than this many lines.
        #[arg(long, default_value_t = 8)]
        min_lines: u64,
        /// Only report duplication that crosses a repository boundary.
        #[arg(long)]
        cross_repo: bool,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// What the catalogue holds, per revision.
    Stats {
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Build or refresh the lexical covers. The only verb that maintains one.
    Index,
    /// The capability question: what do we already have that is about this?
    Search {
        query: String,
        #[arg(long, default_value_t = 8)]
        top: usize,
        /// Which text to rank over: prose, declaration tokens, or both.
        #[arg(long, default_value = "both")]
        r#in: String,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Ask git which commits added or removed an occurrence of an identifier.
    Blame {
        identifier: String,
        /// Repository roots to search. Defaults to the current directory.
        dirs: Vec<PathBuf>,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
}

#[derive(clap::Args)]
struct FilterArgs {
    /// Only declarations of this kind: fn, struct, enum, trait, impl, mod,
    /// use, const, static, type, macro.
    #[arg(long)]
    kind: Option<String>,
    /// Only this repository.
    #[arg(long)]
    repo: Option<String>,
    /// Answer at these revisions: `<repo>@<commit prefix>`, `worktree`, or a
    /// bare commit prefix. Defaults to the newest scan of each repository.
    #[arg(long)]
    at: Option<String>,
}

impl From<FilterArgs> for Filter {
    fn from(args: FilterArgs) -> Self {
        Filter {
            kind: args.kind,
            repo: args.repo,
            revision: Revision::parse(args.at.as_deref()),
        }
    }
}

fn dirs_or_cwd(dirs: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    if dirs.is_empty() {
        return Ok(vec![std::env::current_dir()?]);
    }
    Ok(dirs)
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    if cli.command.is_none() {
        // No subcommand prints usage and performs no write.
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }
    crate::cli::with_output("code", |out| execute(cli, out))
}

pub fn execute(cli: Cli, out: &mut Out<'_>) -> Result<()> {
    let Some(command) = cli.command else {
        return out.text(Cli::command().render_help().to_string());
    };
    let code = Code::new(cli.pile, cli.key);
    match command {
        Command::Ingest {
            dirs,
            commit,
            dry_run,
        } => {
            let dirs = dirs_or_cwd(dirs)?;
            let report = code.ingest(&dirs, &IngestOptions { commit, dry_run })?;
            render::ingest(&report, out)
        }
        Command::Find { name, filter } => {
            let answer = code.find(&name, &filter.into())?;
            render::definition(&answer, out)
        }
        Command::Uses {
            identifier,
            imports,
            filter,
        } => {
            let filter = Filter::from(filter);
            if imports {
                let (count, provenance) = code.imports(&identifier, &filter)?;
                out.line(format!(
                    "{identifier} — first segment of a `use` path in {count} unit(s)"
                ))?;
                out.line("")?;
                return render::provenance(&provenance, out);
            }
            let answer = code.uses(&identifier, &filter)?;
            render::usage(&answer, out)
        }
        Command::Show { selector, source } => {
            let detail = code.show(&selector, source)?;
            render::detail(&detail, out)
        }
        Command::Dup {
            min_lines,
            cross_repo,
            filter,
        } => {
            let report = code.duplicates(min_lines, cross_repo, &filter.into())?;
            render::duplicates(&report, out)
        }
        Command::Stats { filter } => {
            let report = code.stats(&filter.into())?;
            render::stats(&report, out)
        }
        Command::Index => {
            let report = code.index()?;
            render::index(&report, out)
        }
        Command::Search {
            query,
            top,
            r#in,
            filter,
        } => {
            let Some(tier) = Tier::from_name(&r#in) else {
                bail!("--in must be one of: docs, text, both");
            };
            let report = code.search(&query, tier, top, &filter.into())?;
            render::search(&report, out)
        }
        Command::Blame {
            identifier,
            dirs,
            limit,
        } => {
            let dirs = dirs_or_cwd(dirs)?;
            let report = code.blame(&identifier, &dirs, limit)?;
            render::blame(&report, out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_verb_list_is_what_this_faculty_promises() {
        let command = Cli::command();
        let verbs: Vec<String> = command
            .get_subcommands()
            .map(|sub| sub.get_name().to_owned())
            .collect();
        assert_eq!(
            verbs,
            vec!["ingest", "find", "uses", "show", "dup", "stats", "index", "search", "blame",]
        );
    }

    #[test]
    fn no_subcommand_is_a_help_request_and_never_a_write() {
        let parsed = Cli::try_parse_from(["code", "--pile", "/tmp/nonexistent.pile"])
            .expect("the pile argument alone parses");
        assert!(parsed.command.is_none());
    }

    #[test]
    fn a_revision_selector_reaches_the_filter() {
        let parsed = Cli::try_parse_from([
            "code",
            "--pile",
            "/tmp/nonexistent.pile",
            "uses",
            "maintain_admitted_fact_targets",
            "--at",
            "faculties@336a8765",
        ])
        .expect("parses");
        let Some(Command::Uses { filter, .. }) = parsed.command else {
            panic!("expected uses");
        };
        assert_eq!(
            Filter::from(filter).revision,
            Revision::Selector("faculties@336a8765".to_owned())
        );
    }
}
