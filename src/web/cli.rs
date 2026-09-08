//! Explicit shell grammar and local @ inputs for Web.
use super::{presentation, ApiKeys, Provider, Web};
use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum CliProvider {
    Auto,
    Tavily,
    Exa,
}
impl From<CliProvider> for Provider {
    fn from(value: CliProvider) -> Self {
        match value {
            CliProvider::Auto => Self::Auto,
            CliProvider::Tavily => Self::Tavily,
            CliProvider::Exa => Self::Exa,
        }
    }
}
#[derive(Parser)]
#[command(version = crate::GIT_VERSION, name = "web", about = "Web search/browsing faculty (Tavily/Exa)")]
pub(crate) struct Cli {
    /// Existing pile file. Reads and writes never create it.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable collection signer. Ordinary commands never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Override the exact Tavily credential referenced by Headspace. Use
    /// @path for file input or @- for stdin.
    #[arg(long)]
    tavily_api_key: Option<String>,
    /// Override the exact Exa credential referenced by Headspace. Use @path
    /// for file input or @- for stdin.
    #[arg(long)]
    exa_api_key: Option<String>,
    /// Do not write events to the pile; only print results.
    #[arg(long)]
    no_store: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Search the web for a query.
    Search {
        #[arg(help = "Search query. Use @path for file input or @- for stdin.")]
        query: String,
        #[arg(long, default_value_t = 5)]
        max_results: usize,
        #[arg(long, value_enum, default_value_t = CliProvider::Auto)]
        provider: CliProvider,
    },
    /// Fetch and extract a URL (clean text/markdown when supported by provider).
    Fetch {
        url: String,
        #[arg(long, value_enum, default_value_t = CliProvider::Auto)]
        provider: CliProvider,
        /// Max characters to return (provider permitting).
        #[arg(long, default_value_t = 12_000)]
        max_characters: usize,
    },
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };
    let keys = ApiKeys {
        tavily: cli
            .tavily_api_key
            .as_deref()
            .map(|raw| crate::text_arg(raw, "tavily api key").map(|value| value.trim().to_owned()))
            .transpose()?,
        exa: cli
            .exa_api_key
            .as_deref()
            .map(|raw| crate::text_arg(raw, "exa api key").map(|value| value.trim().to_owned()))
            .transpose()?,
    };
    let web = Web::new(cli.pile, cli.key).with_api_keys(keys);
    crate::cli::with_output("web", |out| match command {
        Command::Search {
            query,
            max_results,
            provider,
        } => {
            let query = crate::text_arg(&query, "search query")?;
            let report = web.search(provider.into(), &query, max_results)?;
            presentation::search(&report, out)?;
            if !cli.no_store {
                web.record_search(&report)?;
            }
            Ok(())
        }
        Command::Fetch {
            url,
            provider,
            max_characters,
        } => {
            let report = web.fetch(provider.into(), &url, max_characters)?;
            out.line(&report.content)?;
            if !cli.no_store {
                web.record_fetch(&report)?;
            }
            Ok(())
        }
    })
}
