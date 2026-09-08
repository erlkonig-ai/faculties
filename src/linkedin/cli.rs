//! Tailored LinkedIn CLI. Snapshot paths and token environment/argv input are
//! interpreted only here; shared operations consume resident values.
use super::{operations::*, render, source::parse_snapshot};
use crate::out::Out;
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version = crate::GIT_VERSION, name = "linkedin", about = "LinkedIn → relations import conduit")]
pub struct Cli {
    /// Path to the pile file
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Ingest a LinkedIn snapshot JSON (CONNECTIONS export) into relations.
    Import {
        /// Path to the snapshot JSON (array of connection records).
        snapshot: PathBuf,
        /// Resolve and report, but commit nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Pull connections from the LinkedIn DMA Member Data Portability API
    /// straight into relations. The snapshot's home is the substrate, not a
    /// JSON file — there is no intermediate dump.
    ///
    /// Token is a secret — pass via the LINKEDIN_TOKEN env var (preferred,
    /// not visible in `ps`) or --token. Never piled or committed.
    Pull {
        /// OAuth access token (scope r_dma_portability_self_serve).
        #[arg(long, env = "LINKEDIN_TOKEN", hide_env_values = true)]
        token: String,
        /// Snapshot domain (CONNECTIONS, PROFILE, …).
        #[arg(long, default_value = "CONNECTIONS")]
        domain: String,
        /// Linkedin-Version header — the app's PINNED product version.
        #[arg(long, default_value = "202312")]
        api_version: String,
        /// Resolve and report but commit nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Derive unresolved same-label identity pairs from current Relations state.
    Review {
        /// Max pairs to show.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Record an identity verdict between two people.
    Resolve {
        /// First person id (hex or unambiguous prefix).
        id_a: String,
        /// Second person id (hex or unambiguous prefix).
        id_b: String,
        /// They are the same individual (assert `same_as`).
        #[arg(long, conflicts_with = "distinct")]
        same: bool,
        /// They are different individuals (assert `distinct_from`).
        #[arg(long, conflicts_with = "same")]
        distinct: bool,
    },
}

fn review(value: &ReviewReport, out: &mut Out<'_>) -> Result<()> {
    if value.total == 0 {
        return out.line("No open review candidates. 🎉");
    }
    out.line(format!("{} open review candidate(s):\n", value.total))?;
    for (index, pair) in value.pairs.iter().enumerate() {
        out.line(format!(
            "[{}] ─────────────────────────────────────",
            index + 1
        ))?;
        render::person(&pair.first, out)?;
        out.line("    ~ same person? ~")?;
        render::person(&pair.second, out)?;
        out.line(format!(
            "  → linkedin resolve {:x} {:x} --same | --distinct\n",
            pair.first.person, pair.second.person
        ))?;
    }
    if value.total > value.pairs.len() {
        out.line(format!(
            "(+{} more; raise --limit)",
            value.total - value.pairs.len()
        ))?;
    }
    Ok(())
}

pub fn execute(cli: Cli, out: &mut Out<'_>) -> Result<()> {
    let operations = LinkedIn::new(cli.pile, cli.key);
    match cli.command {
        Command::Import { snapshot, dry_run } => {
            let raw = std::fs::read(&snapshot)
                .with_context(|| format!("read snapshot {}", snapshot.display()))?;
            let connections = parse_snapshot(&raw)?;
            out.line(format!(
                "Read {} connection records from {}",
                connections.len(),
                snapshot.display()
            ))?;
            render::import(&operations.import(&connections, dry_run)?, out)
        }
        Command::Pull {
            token,
            domain,
            api_version,
            dry_run,
        } => {
            out.line(format!(
                "Pulling {domain} (Linkedin-Version {api_version})…"
            ))?;
            let report = operations.with_token(token).pull(PullOptions {
                domain: domain.clone(),
                api_version,
                dry_run,
            })?;
            for notice in &report.notices {
                out.line(notice)?;
            }
            out.line(format!("Fetched {} {domain} record(s).", report.records))?;
            out.line("")?;
            render::import(&report.import, out)
        }
        Command::Review { limit } => review(&operations.review(limit)?, out),
        Command::Resolve {
            id_a,
            id_b,
            same,
            distinct,
        } => {
            if same == distinct {
                bail!("pass exactly one of --same / --distinct");
            }
            render::resolved(&operations.resolve(&id_a, &id_b, same)?, out)
        }
    }
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    crate::cli::with_output("linkedin", |out| execute(cli, out))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_keeps_snapshot_path_and_explicit_mutually_exclusive_verdict_flags() {
        assert!(Cli::try_parse_from([
            "linkedin",
            "--pile",
            "fixture.pile",
            "import",
            "snapshot.json",
            "--dry-run"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "linkedin",
            "--pile",
            "fixture.pile",
            "resolve",
            "ab",
            "cd",
            "--same"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "linkedin",
            "--pile",
            "fixture.pile",
            "resolve",
            "ab",
            "cd",
            "--distinct"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "linkedin",
            "--pile",
            "fixture.pile",
            "resolve",
            "ab",
            "cd",
            "--same",
            "--distinct"
        ])
        .is_err());
    }
}
