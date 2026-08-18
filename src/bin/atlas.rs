use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::atlas::{self, AtlasCatalog, AtlasEntry};
use faculties::atlas_cutover;
use faculties::collection_cutover::{freeze_source, load_signer, open_pile_strict};
use faculties::schemas::atlas::DEFAULT_SCOPE_ID;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::prelude::*;
use faculties::legacy_hint::open_scope;

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "atlas", about = "Schema metadata inspection faculty")]
struct Cli {
    /// Path to the pile file to use.
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
    /// List entities that have metadata::name entries.
    List,
    /// Show metadata for a single id prefix.
    Show { id: String },
    /// Additively publish the stopped legacy `atlas` branch into the fixed
    /// native Atlas collection. Stop every old Atlas writer first.
    MigrateLegacy,
}

#[derive(Clone, Copy)]
struct AtlasStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

impl AtlasStorage<'_> {
    /// Materialize one signer-owned Atlas prefix and keep its attachment
    /// reader under the same open pile lifetime.
    fn with_view<T>(
        &self,
        operation: impl FnOnce(&PileReader, &TribleSet, &AtlasCatalog) -> Result<T>,
    ) -> Result<T> {
        let signer = load_signer(self.pile, self.key)?;
        let pile = open_pile_strict(self.pile)?;
        let mut collection = open_scope(pile, DEFAULT_SCOPE_ID, signer);
        let result = (|| {
            let facts = collection
                .materialize()
                .context("materialize native Atlas collection")?;
            let reader = collection
                .storage_mut()
                .reader()
                .context("open Atlas attachment reader")?;
            let catalog =
                atlas::load_catalog(&reader, &facts).context("validate native Atlas catalog")?;
            operation(&reader, &facts, &catalog)
        })();
        finish_pile(collection.into_storage(), result)
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };
    let storage = AtlasStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
    };

    match command {
        Command::List => cmd_list(storage),
        Command::Show { id } => cmd_show(storage, &id),
        Command::MigrateLegacy => cmd_migrate_legacy(storage),
    }
}

fn cmd_list(storage: AtlasStorage<'_>) -> Result<()> {
    storage.with_view(|_, _, catalog| {
        let mut rows = catalog.entries().collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.names
                .cmp(&right.names)
                .then_with(|| left.id.cmp(&right.id))
        });

        for row in rows {
            let tags = if row.tags.is_empty() {
                String::new()
            } else {
                format!(
                    " [tags: {}]",
                    row.tags
                        .iter()
                        .map(|id| fmt_id(*id))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            let grouped_by = if row.members.is_empty() {
                String::new()
            } else {
                format!(
                    " [groups: {}]",
                    row.members
                        .iter()
                        .map(|id| fmt_id(*id))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            let description = (!row.descriptions.is_empty())
                .then(|| format!(" - {}", row.descriptions.join(" / ")))
                .unwrap_or_default();
            let source_module = (!row.source_modules.is_empty())
                .then(|| format!(" @{}", row.source_modules.join(" / ")))
                .unwrap_or_default();
            let variants = (row.names.len() > 1)
                .then(|| format!(" [{} name variants]", row.names.len()))
                .unwrap_or_default();
            println!(
                "{id} {name}{variants}{source_module}{tags}{grouped_by}{description}",
                id = fmt_id(row.id),
                name = row.names_label(),
            );
        }
        Ok(())
    })
}

fn cmd_show(storage: AtlasStorage<'_>, prefix: &str) -> Result<()> {
    storage.with_view(|_, _, catalog| {
        let row = resolve_prefix(catalog, prefix)?;

        println!("id: {:x}", row.id);
        for name in &row.names {
            println!("name: {name}");
        }
        for description in &row.descriptions {
            println!("description: {description}");
        }
        for source_module in &row.source_modules {
            println!("source_module: {source_module}");
        }
        if !row.tags.is_empty() {
            println!(
                "tags: {}",
                row.tags
                    .iter()
                    .map(|id| format!("{id:x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !row.members.is_empty() {
            println!(
                "grouped_by: {}",
                row.members
                    .iter()
                    .map(|id| format!("{id:x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        Ok(())
    })
}

fn cmd_migrate_legacy(storage: AtlasStorage<'_>) -> Result<()> {
    // Fail on missing authority before taking the stopped source snapshot.
    load_signer(storage.pile, storage.key)?;
    let existing = storage.with_view(|_, facts, _| Ok(facts.clone()))?;
    let source = freeze_source(storage.pile)
        .context("freeze legacy Atlas source; every old Atlas writer must be stopped")?;
    let fingerprint = source.fingerprint();
    let plan = atlas_cutover::plan(&source)?;
    let mut expected = existing;
    expected += plan.original_facts().clone();

    let commits = atlas_cutover::publish(&source, &plan, storage.pile, storage.key)?;
    let refreshed = freeze_source(storage.pile)?;
    if refreshed.fingerprint() != fingerprint {
        bail!(
            "legacy Atlas pins changed during migration; published commits are replay-safe, stop every writer and retry"
        );
    }
    let actual = storage.with_view(|_, facts, _| Ok(facts.clone()))?;
    if actual != expected {
        bail!("Atlas migration result is not prior native value union exact legacy facts");
    }

    println!(
        "migrated {} authored Atlas commit{} ({} authored empty, {} verified contentless merge{}): {} exact facts in scope {DEFAULT_SCOPE_ID:X}",
        commits.len(),
        if commits.len() == 1 { "" } else { "s" },
        plan.report().authored_empty_commits,
        plan.report().contentless_merges,
        if plan.report().contentless_merges == 1 { "" } else { "s" },
        plan.report().facts,
    );
    println!("legacy branch retained as inert evidence; native commands no longer consult it");
    Ok(())
}

fn resolve_prefix<'a>(catalog: &'a AtlasCatalog, prefix: &str) -> Result<&'a AtlasEntry> {
    let prefix = prefix.trim().to_lowercase();
    if prefix.is_empty() {
        bail!("id prefix is empty");
    }
    let mut matches = catalog
        .entries()
        .filter(|entry| format!("{:x}", entry.id).starts_with(&prefix));
    let first = matches.next();
    match (first, matches.next()) {
        (None, _) => bail!("no id matches prefix '{prefix}'"),
        (Some(entry), None) => Ok(entry),
        (Some(_), Some(_)) => bail!("multiple ids match prefix '{prefix}'"),
    }
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    match (result, pile.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(anyhow!("close Atlas pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Atlas pile also failed: {close_error}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permanent_cli_exposes_no_scope_branch_or_repair_knobs() {
        let command = Cli::command();
        for forbidden in ["scope", "branch", "branch_id", "head", "repair"] {
            assert!(!command
                .get_arguments()
                .any(|argument| argument.get_id() == forbidden));
        }
        assert!(command
            .get_arguments()
            .any(|argument| argument.get_id() == "key"));
    }
}
