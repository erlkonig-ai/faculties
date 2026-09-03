use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use faculties::clock;
use faculties::collection_names::open_configured;
use faculties::schemas::headspace::{
    playground_config, DEFAULT_SCOPE_ID as HEADSPACE_SCOPE_ID, KIND_CONFIG_ID, KIND_LIVE_RECORD,
};
use faculties::schemas::web::{web_schema, DEFAULT_SCOPE_ID};
use faculties::secrets::storage as vaults;
use faculties::storage::{load_signer, open_pile_strict, FactArchive, FactCollection};
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::json;
use triblespace::core::collection::{CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::Pile;
use triblespace::macros::{find, pattern};
use triblespace::prelude::inlineencodings::NsTAIInterval;
use triblespace::prelude::*;

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Provider {
    Auto,
    Tavily,
    Exa,
}

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "web", about = "Web search/browsing faculty (Tavily/Exa)")]
struct Cli {
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
        #[arg(long, value_enum, default_value_t = Provider::Auto)]
        provider: Provider,
    },
    /// Fetch and extract a URL (clean text/markdown when supported by provider).
    Fetch {
        url: String,
        #[arg(long, value_enum, default_value_t = Provider::Auto)]
        provider: Provider,
        /// Max characters to return (provider permitting).
        #[arg(long, default_value_t = 12_000)]
        max_characters: usize,
    },
}

#[derive(Clone, Debug, Default)]
struct ApiKeys {
    tavily: Option<String>,
    exa: Option<String>,
}

/// The exact immutable credential versions named by one Web-visible
/// Headspace frontier.
///
/// Sets are intentional: TribleSpace does not impose attribute cardinality.
/// Repeated values remain useful alternatives rather than invalidating the
/// collection, while genuinely divergent frontier heads remain visible.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct WebSecretVersions {
    tavily: BTreeSet<Id>,
    exa: BTreeSet<Id>,
}

fn main() -> Result<()> {
    run(Cli::parse())
}

fn run(cli: Cli) -> Result<()> {
    let Some(cmd) = cli.command.as_ref() else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };

    let storage = WebStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
    };
    let requested_provider = match cmd {
        Command::Search { provider, .. } | Command::Fetch { provider, .. } => *provider,
    };
    let keys = resolve_api_keys(&cli, storage, requested_provider)?;

    match cmd {
        Command::Search {
            query,
            max_results,
            provider,
        } => {
            let query = load_value_or_file(query, "search query")?;
            cmd_search(&cli, storage, keys, *provider, &query, *max_results)
        }
        Command::Fetch {
            url,
            provider,
            max_characters,
        } => cmd_fetch(&cli, storage, keys, *provider, url, *max_characters),
    }
}

fn resolve_api_keys(
    cli: &Cli,
    storage: WebStorage<'_>,
    requested_provider: Provider,
) -> Result<ApiKeys> {
    let mut tavily = cli
        .tavily_api_key
        .as_deref()
        .map(|value| load_value_or_file_trimmed(value, "tavily api key"))
        .transpose()?;
    let mut exa = cli
        .exa_api_key
        .as_deref()
        .map(|value| load_value_or_file_trimmed(value, "exa api key"))
        .transpose()?;
    let needs_headspace = match requested_provider {
        Provider::Auto => tavily.is_none() || exa.is_none(),
        Provider::Tavily => tavily.is_none(),
        Provider::Exa => exa.is_none(),
    };
    if needs_headspace {
        let configured = storage.open_web_secrets()?;
        tavily = tavily.or(configured.tavily);
        exa = exa.or(configured.exa);
    }
    Ok(ApiKeys { tavily, exa })
}

fn cmd_search(
    cli: &Cli,
    storage: WebStorage<'_>,
    keys: ApiKeys,
    provider: Provider,
    query: &str,
    max_results: usize,
) -> Result<()> {
    let provider = choose_provider(provider, &keys)?;
    let client = Client::builder()
        .user_agent("playground-web-faculty/0")
        .build()
        .context("build http client")?;

    let results = match provider {
        Provider::Tavily => {
            tavily_search(&client, keys.tavily.as_deref().unwrap(), query, max_results)?
        }
        Provider::Exa => exa_search(&client, keys.exa.as_deref().unwrap(), query, max_results)?,
        Provider::Auto => unreachable!("choose_provider resolves Auto"),
    };

    print_search_results(provider, query, &results);

    if !cli.no_store {
        storage.store(
            search_fragment(provider, query, &results, clock::point_now()?)?,
            "web search observation",
        )?;
    }
    Ok(())
}

fn cmd_fetch(
    cli: &Cli,
    storage: WebStorage<'_>,
    keys: ApiKeys,
    provider: Provider,
    url: &str,
    max_characters: usize,
) -> Result<()> {
    let provider = choose_provider_fetch(provider, &keys)?;
    let client = Client::builder()
        .user_agent("playground-web-faculty/0")
        .build()
        .context("build http client")?;

    let content = match provider {
        Provider::Tavily => tavily_extract(&client, keys.tavily.as_deref().unwrap(), url)?,
        Provider::Exa => exa_contents(&client, keys.exa.as_deref().unwrap(), url, max_characters)?,
        Provider::Auto => unreachable!("choose_provider resolves Auto"),
    };

    println!("{content}");

    if cli.no_store {
        return Ok(());
    }
    storage.store(
        fetch_fragment(provider, url, &content, clock::point_now()?),
        "web fetch observation",
    )
}

fn choose_provider(provider: Provider, keys: &ApiKeys) -> Result<Provider> {
    match provider {
        Provider::Tavily => {
            if keys.tavily.is_none() {
                bail!(
                    "no Tavily credential available (attach an exact Headspace secret or pass --tavily-api-key)"
                );
            }
            Ok(Provider::Tavily)
        }
        Provider::Exa => {
            if keys.exa.is_none() {
                bail!(
                    "no Exa credential available (attach an exact Headspace secret or pass --exa-api-key)"
                );
            }
            Ok(Provider::Exa)
        }
        Provider::Auto => {
            if keys.tavily.is_some() {
                Ok(Provider::Tavily)
            } else if keys.exa.is_some() {
                Ok(Provider::Exa)
            } else {
                bail!(
                    "no Web provider credential is referenced by Headspace or explicitly supplied"
                );
            }
        }
    }
}

fn choose_provider_fetch(provider: Provider, keys: &ApiKeys) -> Result<Provider> {
    match provider {
        Provider::Auto => {
            if keys.exa.is_some() {
                Ok(Provider::Exa)
            } else if keys.tavily.is_some() {
                Ok(Provider::Tavily)
            } else {
                bail!(
                    "no Web provider credential is referenced by Headspace or explicitly supplied"
                );
            }
        }
        other => choose_provider(other, keys),
    }
}

#[derive(Clone, Copy)]
struct WebStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

impl WebStorage<'_> {
    /// Resolve Headspace once and decrypt exactly the credential versions it
    /// names. Labels and timestamps never participate in runtime selection.
    fn open_web_secrets(&self) -> Result<ApiKeys> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = (|| {
            let source = open_configured(&mut pile, HEADSPACE_SCOPE_ID, signer.verifying_key())?;
            let headspace = FactCollection::new(&mut pile, source)
                .context("register maintained Headspace fact collection")?;

            // One frozen source watermark decides which Headspace support this
            // command may observe. Maintenance can append physical views, but
            // cannot move that semantic boundary.
            let before = pile
                .snapshot()
                .context("freeze Headspace source snapshot")?;
            let instant = clock::now()?;
            let support = before
                .collection_at(headspace.source(), instant)
                .context("observe resident Headspace collection")?
                .support()
                .clone();
            drop(before);
            drop(
                headspace
                    .maintain_exact(&mut pile, &support)
                    .context("maintain Headspace fact collection")?,
            );

            let secrets = vaults::discover_local_vaults(&mut pile, &signer)
                .context("discover readable Secrets vaults")?;

            // Secrets discovery owns a later immutable pile snapshot. Attach
            // the exact maintained Headspace support through that same world,
            // then project only the facts Web actually consumes.
            let reader = secrets.snapshot().store_snapshot();
            let facts = reader
                .collection_exact(headspace.rank9(), &support)
                .context("attach maintained Headspace collection")?
                .view::<FactArchive>()
                .context("read maintained Headspace collection")?;
            let versions = web_secret_versions(&facts)?;

            Ok(ApiKeys {
                tavily: open_web_secret(&secrets, &signer, &versions.tavily, "Tavily")?,
                exa: open_web_secret(&secrets, &signer, &versions.exa, "Exa")?,
            })
        })();
        finish_pile(pile, result, "credential read")
    }

    fn store(&self, mut fragment: Fragment, description: &'static str) -> Result<()> {
        let signer = load_signer(self.pile, self.key)?;
        fragment.describe_with(entity! { metadata::description: description });
        let mut pile = open_pile_strict(self.pile)?;
        let collection = open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
        let result = pile
            .commit(collection, &signer, fragment)
            .context("commit Web observation")
            .map(|_| ());
        finish_pile(pile, result, "observation write")
    }
}

/// Query the current Headspace Web-credential projection without loading a
/// second catalog beside TribleSpace.
///
/// A snapshot participates when its two type tags are present and decodable.
/// Additional facts are open-world annotations. Entity ids are opaque: the
/// projection never reconstructs or validates an intrinsic root. The only
/// cross-row semantic retained here is Headspace's explicit supersession DAG;
/// concurrent heads may agree on this Web-specific projection, while a real
/// credential fork is surfaced rather than arbitrated by arrival order.
fn web_secret_versions<P>(facts: &P) -> Result<WebSecretVersions>
where
    P: TriblePattern + ?Sized,
{
    let configs = find!(
        id: Id,
        pattern!(facts, [{ ?id @
            metadata::tag: KIND_LIVE_RECORD,
            metadata::tag: KIND_CONFIG_ID,
        }])
    )
    .collect::<BTreeSet<_>>();
    if configs.is_empty() {
        return Ok(WebSecretVersions::default());
    }

    let superseded = find!(
        (successor: Id, predecessor: Id),
        pattern!(facts, [{ ?successor @ metadata::supersedes: ?predecessor }])
    )
    .filter_map(|(successor, predecessor)| {
        (configs.contains(&successor) && configs.contains(&predecessor)).then_some(predecessor)
    })
    .collect::<BTreeSet<_>>();

    let mut frontier = configs.difference(&superseded).copied();
    let Some(first) = frontier.next() else {
        bail!("Headspace Web credential track has no current state");
    };
    let selected = web_secret_versions_at(facts, first);
    for head in frontier {
        if web_secret_versions_at(facts, head) != selected {
            bail!("Headspace Web credential configuration is forked");
        }
    }
    Ok(selected)
}

fn web_secret_versions_at<P>(facts: &P, config: Id) -> WebSecretVersions
where
    P: TriblePattern + ?Sized,
{
    WebSecretVersions {
        tavily: find!(
            version: Id,
            pattern!(facts, [{ config @ playground_config::tavily_secret_version: ?version }])
        )
        .collect(),
        exa: find!(
            version: Id,
            pattern!(facts, [{ config @ playground_config::exa_secret_version: ?version }])
        )
        .collect(),
    }
}

/// Open the first usable exact credential reference in canonical id order.
///
/// Repeated attribute values are alternatives, not a cardinality error. A
/// reference that is absent from this local Secrets view therefore does not
/// mask another usable reference asserted on the same Headspace state.
fn open_web_secret(
    secrets: &vaults::VaultDiscovery,
    signer: &SigningKey,
    versions: &BTreeSet<Id>,
    role: &str,
) -> Result<Option<String>> {
    let mut failures = Vec::new();
    for version in versions {
        match secrets.snapshot().open(*version, signer) {
            Ok(plaintext) => match String::from_utf8(plaintext) {
                Ok(value) => return Ok(Some(value)),
                Err(error) => failures.push(format!("{version:x}: not UTF-8 ({error})")),
            },
            Err(error) => failures.push(format!("{version:x}: {error:#}")),
        }
    }
    if failures.is_empty() {
        Ok(None)
    } else {
        bail!(
            "no referenced {role} Secrets version is locally usable: {}",
            failures.join("; ")
        )
    }
}

fn finish_pile<T>(pile: Pile, result: Result<T>, operation: &str) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context(format!("close Web pile after {operation}"))),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Web pile after {operation} also failed: {close_error}"
        ))),
    }
}

#[derive(Clone, Debug)]
struct SearchResult {
    url: String,
    title: Option<String>,
    snippet: Option<String>,
}

fn print_search_results(provider: Provider, query: &str, results: &[SearchResult]) {
    let provider_name = provider_name(provider);
    println!("provider: {provider_name}");
    println!("query: {query}");
    println!("results: {}", results.len());
    println!();
    for (idx, r) in results.iter().enumerate() {
        println!(
            "[{}] {}",
            idx + 1,
            r.title.as_deref().unwrap_or("<no title>")
        );
        println!("url: {}", r.url);
        if let Some(snippet) = r.snippet.as_deref().filter(|s| !s.is_empty()) {
            println!("snippet: {}", snippet.trim());
        }
        println!();
    }
}

fn provider_name(provider: Provider) -> &'static str {
    match provider {
        Provider::Tavily => "tavily",
        Provider::Exa => "exa",
        Provider::Auto => "auto",
    }
}

fn search_fragment(
    provider: Provider,
    query: &str,
    results: &[SearchResult],
    observed_at: Inline<NsTAIInterval>,
) -> Result<Fragment> {
    let mut fragment = Fragment::empty();
    let query_handle = fragment.put(query.to_owned());
    let mut result_ids = Vec::with_capacity(results.len());

    for result in results {
        let url_handle = fragment.put(result.url.clone());
        let title_handle = result
            .title
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| fragment.put(value.to_owned()));
        let snippet_handle = result
            .snippet
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| fragment.put(value.to_owned()));
        let result_fragment = entity! { _ @
            metadata::tag: &web_schema::kind_result,
            web_schema::url: url_handle,
            web_schema::title?: title_handle,
            web_schema::snippet?: snippet_handle,
        };
        result_ids.push(
            result_fragment
                .root()
                .ok_or_else(|| anyhow!("Web result fragment has no intrinsic root"))?,
        );
        fragment += result_fragment;
    }
    fragment += entity! { _ @
        metadata::tag: &web_schema::kind_search,
        web_schema::query: query_handle,
        web_schema::provider: provider_name(provider),
        metadata::created_at: observed_at,
        web_schema::result*: result_ids,
    };
    Ok(fragment)
}

fn fetch_fragment(
    provider: Provider,
    url: &str,
    content: &str,
    observed_at: Inline<NsTAIInterval>,
) -> Fragment {
    let mut fragment = Fragment::empty();
    let url = fragment.put(url.to_owned());
    let content = fragment.put(content.to_owned());
    fragment += entity! { _ @
        metadata::tag: &web_schema::kind_fetch,
        web_schema::provider: provider_name(provider),
        metadata::created_at: observed_at,
        web_schema::url: url,
        web_schema::content: content,
    };
    fragment
}

// --- Tavily ---

#[derive(Deserialize)]
struct TavilySearchResponse {
    results: Vec<TavilyResult>,
}

#[derive(Deserialize)]
struct TavilyResult {
    url: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    content: String,
}

fn tavily_search(
    client: &Client,
    api_key: &str,
    query: &str,
    max_results: usize,
) -> Result<Vec<SearchResult>> {
    let resp: TavilySearchResponse = client
        .post("https://api.tavily.com/search")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {api_key}"))
        .json(&json!({
            "query": query,
            "search_depth": "basic",
            "max_results": max_results,
            "include_answer": false,
            "include_raw_content": false,
        }))
        .send()
        .context("tavily search request")?
        .error_for_status()
        .context("tavily search status")?
        .json()
        .context("tavily search json")?;

    Ok(resp
        .results
        .into_iter()
        .map(|r| SearchResult {
            url: r.url,
            title: Some(r.title).filter(|s| !s.is_empty()),
            snippet: Some(r.content).filter(|s| !s.is_empty()),
        })
        .collect())
}

#[derive(Deserialize)]
struct TavilyExtractResponse {
    results: Vec<TavilyExtractResult>,
}

#[derive(Deserialize)]
struct TavilyExtractResult {
    #[allow(dead_code)]
    url: String,
    #[serde(default)]
    raw_content: String,
    #[serde(default)]
    content: String,
}

fn tavily_extract(client: &Client, api_key: &str, url: &str) -> Result<String> {
    let resp: TavilyExtractResponse = client
        .post("https://api.tavily.com/extract")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {api_key}"))
        .json(&json!({
            "urls": [url],
            "extract_depth": "basic",
            "format": "markdown",
        }))
        .send()
        .context("tavily extract request")?
        .error_for_status()
        .context("tavily extract status")?
        .json()
        .context("tavily extract json")?;

    let Some(first) = resp.results.into_iter().next() else {
        bail!("tavily extract returned no results");
    };
    let text = if !first.raw_content.is_empty() {
        first.raw_content
    } else {
        first.content
    };
    Ok(text)
}

// --- Exa ---

#[derive(Deserialize)]
struct ExaSearchResponse {
    results: Vec<ExaResult>,
}

#[derive(Deserialize)]
struct ExaResult {
    url: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    text: String,
}

fn exa_search(
    client: &Client,
    api_key: &str,
    query: &str,
    max_results: usize,
) -> Result<Vec<SearchResult>> {
    let resp: ExaSearchResponse = client
        .post("https://api.exa.ai/search")
        .header(CONTENT_TYPE, "application/json")
        .header("x-api-key", api_key)
        .json(&json!({
            "query": query,
            "numResults": max_results,
            "text": false,
        }))
        .send()
        .context("exa search request")?
        .error_for_status()
        .context("exa search status")?
        .json()
        .context("exa search json")?;

    Ok(resp
        .results
        .into_iter()
        .map(|r| SearchResult {
            url: r.url,
            title: Some(r.title).filter(|s| !s.is_empty()),
            snippet: Some(r.text).filter(|s| !s.is_empty()),
        })
        .collect())
}

#[derive(Deserialize)]
struct ExaContentsResponse {
    results: Vec<ExaContentsResult>,
}

#[derive(Deserialize)]
struct ExaContentsResult {
    #[allow(dead_code)]
    url: String,
    #[serde(default)]
    text: String,
}

fn exa_contents(
    client: &Client,
    api_key: &str,
    url: &str,
    max_characters: usize,
) -> Result<String> {
    let resp: ExaContentsResponse = client
        .post("https://api.exa.ai/contents")
        .header(CONTENT_TYPE, "application/json")
        .header("x-api-key", api_key)
        .json(&json!({
            "urls": [url],
            "text": {
                "maxCharacters": max_characters,
                "includeHtmlTags": false,
            },
        }))
        .send()
        .context("exa contents request")?
        .error_for_status()
        .context("exa contents status")?
        .json()
        .context("exa contents json")?;

    let Some(first) = resp.results.into_iter().next() else {
        bail!("exa contents returned no results");
    };
    Ok(first.text)
}

fn load_value_or_file(raw: &str, label: &str) -> Result<String> {
    if let Some(path) = raw.strip_prefix('@') {
        if path == "-" {
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .with_context(|| format!("read {label} from stdin"))?;
            return Ok(value);
        }
        return fs::read_to_string(path).with_context(|| format!("read {label} from {path}"));
    }
    Ok(raw.to_string())
}

fn load_value_or_file_trimmed(raw: &str, label: &str) -> Result<String> {
    Ok(load_value_or_file(raw, label)?.trim().to_string())
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use hifitime::Epoch;

    use super::*;
    use faculties::storage::{initialize_signer, open_pile_strict};

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn config_fragment(
        id: Id,
        predecessor: Option<Id>,
        tavily: Option<Id>,
        exa: Option<Id>,
    ) -> Fragment {
        entity! { ExclusiveId::force_ref(&id) @
            metadata::tag: &KIND_LIVE_RECORD,
            metadata::tag: &KIND_CONFIG_ID,
            metadata::supersedes?: predecessor,
            playground_config::tavily_secret_version?: tavily,
            playground_config::exa_secret_version?: exa,
        }
    }

    #[test]
    fn cli_exposes_one_fixed_collection_without_legacy_coordinates() {
        let command = Cli::command();
        command.clone().debug_assert();
        let arguments = command
            .get_arguments()
            .map(|argument| argument.get_id().as_str().to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(arguments.contains("key"));
        assert!(!arguments.contains("secrets_identity"));
        assert!(!arguments.contains("branch_id"));
        assert!(!arguments.contains("scope"));
    }

    #[test]
    fn explicit_provider_override_does_not_require_headspace_or_a_pile() {
        let missing = PathBuf::from("/definitely/not/a/web-test.pile");
        let cli = Cli {
            pile: missing.clone(),
            key: None,
            tavily_api_key: Some(" explicit-tavily-key ".to_owned()),
            exa_api_key: None,
            no_store: true,
            command: None,
        };
        let keys = resolve_api_keys(
            &cli,
            WebStorage {
                pile: &missing,
                key: None,
            },
            Provider::Tavily,
        )
        .unwrap();
        assert_eq!(keys.tavily.as_deref(), Some("explicit-tavily-key"));
        assert!(keys.exa.is_none());
    }

    #[test]
    fn web_credential_projection_uses_opaque_ids_and_the_current_frontier() {
        let old = id(0x91);
        let current = id(0x92);
        let old_tavily = id(0x93);
        let current_tavily = id(0x94);
        let current_exa = id(0x95);
        let mut fragment = config_fragment(old, None, Some(old_tavily), None);
        fragment += config_fragment(current, Some(old), Some(current_tavily), Some(current_exa));

        let projected = web_secret_versions(fragment.facts()).unwrap();
        assert_eq!(projected.tavily, BTreeSet::from([current_tavily]));
        assert_eq!(projected.exa, BTreeSet::from([current_exa]));
    }

    #[test]
    fn repeated_credential_values_are_alternatives_not_a_cardinality_error() {
        let config = id(0xa1);
        let first = id(0xa2);
        let second = id(0xa3);
        let mut fragment = config_fragment(config, None, Some(first), None);
        fragment += entity! { ExclusiveId::force_ref(&config) @
            playground_config::tavily_secret_version: &second,
        };

        let projected = web_secret_versions(fragment.facts()).unwrap();
        assert_eq!(projected.tavily, BTreeSet::from([first, second]));
    }

    #[test]
    fn divergent_web_credential_frontiers_remain_visible() {
        let mut fragment = config_fragment(id(0xb1), None, Some(id(0xb2)), None);
        fragment += config_fragment(id(0xb3), None, Some(id(0xb4)), None);

        assert!(web_secret_versions(fragment.facts())
            .unwrap_err()
            .to_string()
            .contains("forked"));
    }

    #[test]
    fn search_fragment_composes_results_into_one_commit_payload() {
        let fragment = search_fragment(
            Provider::Tavily,
            "canonical collections",
            &[
                SearchResult {
                    url: "https://one.test".to_owned(),
                    title: Some("one".to_owned()),
                    snippet: None,
                },
                SearchResult {
                    url: "https://two.test".to_owned(),
                    title: None,
                    snippet: Some("two".to_owned()),
                },
            ],
            clock::point(Epoch::from_unix_seconds(1.0)).unwrap(),
        )
        .unwrap();

        let facts = fragment.facts();
        let result_entities = find!(
            (entity: Id),
            pattern!(facts, [{ ?entity @ metadata::tag: web_schema::kind_result }])
        )
        .collect::<Vec<_>>();
        let searches = find!(
            (entity: Id, result: Id),
            pattern!(facts, [{
                ?entity @
                metadata::tag: web_schema::kind_search,
                web_schema::result: ?result,
            }])
        )
        .collect::<Vec<_>>();
        assert_eq!(result_entities.len(), 2);
        assert_eq!(searches.len(), 2);
        assert_eq!(
            searches
                .iter()
                .map(|(entity, _)| *entity)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            1
        );
    }

    #[test]
    fn storage_publishes_directly_to_the_native_web_collection() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("web.pile");
        let key_path = directory.path().join("web.key");
        File::create(&pile_path).unwrap();
        initialize_signer(&pile_path, Some(&key_path)).unwrap();

        WebStorage {
            pile: &pile_path,
            key: Some(&key_path),
        }
        .store(
            fetch_fragment(
                Provider::Exa,
                "https://example.test",
                "body",
                clock::point(Epoch::from_unix_seconds(1.0)).unwrap(),
            ),
            "test Web observation",
        )
        .unwrap();

        let signer = load_signer(&pile_path, Some(&key_path)).unwrap();
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let source =
            faculties::collection_names::open(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())
                .unwrap();
        let collection = FactCollection::new(&mut pile, source).unwrap();
        let before = pile.snapshot().unwrap();
        let instant = clock::now().unwrap();
        let store_snapshot = collection.maintain_at(&mut pile, &before, instant).unwrap();
        let facts = store_snapshot
            .collection_at(collection.rank9(), instant)
            .unwrap()
            .view::<FactArchive>()
            .unwrap();
        assert_eq!(
            find!(
                (entity: Id),
                pattern!(&facts, [{ ?entity @ metadata::tag: web_schema::kind_fetch }])
            )
            .count(),
            1
        );
        pile.close().unwrap();
    }
}
