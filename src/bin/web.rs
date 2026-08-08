use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use faculties::collection_access;
use faculties::headspace;
use faculties::schemas::headspace::DEFAULT_SCOPE_ID as HEADSPACE_SCOPE_ID;
use faculties::schemas::web::{web_schema, DEFAULT_SCOPE_ID};
use hifitime::Epoch;
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::json;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval};
use triblespace::prelude::*;

const LEGACY_WEB_BRANCH_NAME: &str = "web";

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Provider {
    Auto,
    Tavily,
    Exa,
}

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "web", about = "Web search/browsing faculty (Tavily/Exa)")]
struct Cli {
    /// Path to the pile file to use.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Stored results never create it;
    /// initialize explicitly with `trible pile signing-key init <pile>`.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Extrinsic collection scope for stored searches and fetches. Defaults to
    /// the stable web scope declared by this faculty.
    #[arg(long, value_parser = parse_id_arg)]
    scope: Option<Id>,
    /// Override Tavily API key (otherwise loaded from config.tavily_api_key). Use @path for file input or @- for stdin.
    #[arg(long)]
    tavily_api_key: Option<String>,
    /// Override Exa API key (otherwise loaded from config.exa_api_key). Use @path for file input or @- for stdin.
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
    /// Publish the signed legacy `web` branch as collection commits, then
    /// verify the exact materialized view. Stop every legacy web writer and
    /// every collection-native writer using the same target scope before
    /// running this command. It never removes the legacy pin.
    MigrateLegacy {
        /// Exact legacy web branch id. Needed only when duplicate `web`
        /// branch names make name lookup ambiguous.
        #[arg(long, value_parser = parse_id_arg)]
        legacy_branch_id: Option<Id>,
    },
}

#[derive(Clone, Default)]
struct ApiKeys {
    tavily: Option<String>,
    exa: Option<String>,
}

#[derive(Clone, Default)]
struct ConfigSnapshot {
    tavily_api_key: Option<String>,
    exa_api_key: Option<String>,
}

fn parse_id_arg(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim()).ok_or_else(|| format!("invalid id '{raw}'"))
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
        scope: cli.scope.unwrap_or(DEFAULT_SCOPE_ID),
    };

    if let Command::MigrateLegacy { legacy_branch_id } = cmd {
        return cmd_migrate_legacy(storage, *legacy_branch_id);
    }

    let config = load_config_snapshot(&cli.pile, cli.key.as_deref())?;
    let keys = resolve_api_keys(&cli, &config)?;

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
        Command::MigrateLegacy { .. } => unreachable!("handled before provider configuration"),
    }
}

fn resolve_api_keys(cli: &Cli, config: &ConfigSnapshot) -> Result<ApiKeys> {
    let tavily = cli
        .tavily_api_key
        .as_deref()
        .map(|value| load_value_or_file_trimmed(value, "tavily api key"))
        .transpose()?
        .or_else(|| config.tavily_api_key.clone());
    let exa = cli
        .exa_api_key
        .as_deref()
        .map(|value| load_value_or_file_trimmed(value, "exa api key"))
        .transpose()?
        .or_else(|| config.exa_api_key.clone());
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

    store_search_if_enabled(cli.no_store, storage, provider, query, &results)
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

    store_fetch_if_enabled(cli.no_store, storage, provider, url, &content)
}

fn choose_provider(provider: Provider, keys: &ApiKeys) -> Result<Provider> {
    match provider {
        Provider::Tavily => {
            if keys.tavily.is_none() {
                bail!("no Tavily API key configured");
            }
            Ok(Provider::Tavily)
        }
        Provider::Exa => {
            if keys.exa.is_none() {
                bail!("no Exa API key configured");
            }
            Ok(Provider::Exa)
        }
        Provider::Auto => {
            if keys.tavily.is_some() {
                Ok(Provider::Tavily)
            } else if keys.exa.is_some() {
                Ok(Provider::Exa)
            } else {
                bail!("no web provider configured (set config.tavily_api_key and/or config.exa_api_key)");
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
                bail!("no web provider configured (set config.tavily_api_key and/or config.exa_api_key)");
            }
        }
        other => choose_provider(other, keys),
    }
}

fn load_config_snapshot(pile_path: &Path, key_path: Option<&Path>) -> Result<ConfigSnapshot> {
    let debug = std::env::var_os("PLAYGROUND_WEB_DEBUG").is_some();
    let signer = collection_access::load_signer(pile_path, key_path)?;
    let allowed = HashSet::from([signer.verifying_key()]);
    let snapshot = collection_access::CollectionSnapshot::open(pile_path)?;
    let view = snapshot.materialize_scope(HEADSPACE_SCOPE_ID, &allowed)?;
    let catalog = headspace::project_result(&view.reader, &view.facts)?;
    let Some(config) = catalog.config.settled_value("Headspace config")? else {
        return Ok(ConfigSnapshot::default());
    };
    if debug {
        eprintln!("[web] resolved immutable Headspace config");
    }
    Ok(ConfigSnapshot {
        tavily_api_key: config.tavily_api_key.clone(),
        exa_api_key: config.exa_api_key.clone(),
    })
}

#[derive(Clone, Debug)]
struct SearchResult {
    url: String,
    title: Option<String>,
    snippet: Option<String>,
}

fn provider_name(provider: Provider) -> &'static str {
    match provider {
        Provider::Tavily => "tavily",
        Provider::Exa => "exa",
        Provider::Auto => "auto",
    }
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

#[derive(Clone, Copy)]
struct WebStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
    scope: Id,
}

impl WebStorage<'_> {
    fn publish(&self, fragment: Fragment, message: &str) -> Result<CollectionCommit> {
        let metadata = entity! { metadata::description: message.to_owned() };
        collection_access::publish_fragment(self.pile, self.key, self.scope, fragment, metadata)
    }
}

fn preflight_legacy_web_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts {
        let field = if fact.a() == &web_schema::query.id() {
            Some("web::query")
        } else if fact.a() == &web_schema::url.id() {
            Some("web::url")
        } else if fact.a() == &web_schema::title.id() {
            Some("web::title")
        } else if fact.a() == &web_schema::snippet.id() {
            Some("web::snippet")
        } else if fact.a() == &web_schema::content.id() {
            Some("web::content")
        } else {
            None
        };
        let Some(field) = field else {
            continue;
        };
        let handle = *fact.v::<Handle<LongString>>();
        let _: View<str> = reader.get(handle).with_context(|| {
            format!(
                "strictly read legacy {field} payload {}",
                hex::encode_upper(handle.raw)
            )
        })?;
    }
    Ok(())
}

fn migrate_legacy(
    storage: WebStorage<'_>,
    explicit_branch: Option<Id>,
) -> Result<collection_access::LegacyMigrationReport> {
    collection_access::migrate_legacy_simplearchive_branch(
        storage.pile,
        storage.key,
        storage.scope,
        LEGACY_WEB_BRANCH_NAME,
        explicit_branch,
        preflight_legacy_web_payloads,
        |_, _| Ok(()),
    )
}

fn cmd_migrate_legacy(storage: WebStorage<'_>, explicit_branch: Option<Id>) -> Result<()> {
    let report = migrate_legacy(storage, explicit_branch)?;
    println!(
        "migrated {} authored commit{} ({} facts); skipped {} contentless merge{}",
        report.commits.len(),
        if report.commits.len() == 1 { "" } else { "s" },
        report.facts,
        report.skipped_merges,
        if report.skipped_merges == 1 { "" } else { "s" },
    );
    println!("  legacy branch {}", report.branch_id);
    println!(
        "  legacy head   {}",
        report
            .head
            .map(|head| hex::encode_upper(head.raw))
            .unwrap_or_else(|| "<empty>".to_owned())
    );
    println!(
        "  retention     {} direct + {} recursive roots (verified, not persisted)",
        report.retention_direct, report.retention_recursive
    );
    println!("  legacy pin remains in place until recurring retention policy exists");
    Ok(())
}

fn search_fragment(
    provider: Provider,
    query: &str,
    results: &[SearchResult],
    created_at: Inline<NsTAIInterval>,
) -> Result<Fragment> {
    let mut search = Fragment::empty();
    let mut result_ids = Vec::with_capacity(results.len());

    for result in results {
        let title = result
            .title
            .as_ref()
            .filter(|value| !value.is_empty())
            .cloned();
        let snippet = result.snippet.as_ref().filter(|value| !value.is_empty());
        let snippet = snippet.cloned();
        let result_fragment = entity! { _ @
            metadata::tag: &web_schema::kind_result,
            web_schema::url: result.url.clone(),
            web_schema::title?: title,
            web_schema::snippet?: snippet,
        };
        let result_id = result_fragment
            .root()
            .ok_or_else(|| anyhow!("result fragment missing root export"))?;
        result_ids.push(result_id);
        search += result_fragment;
    }

    search += entity! { _ @
        metadata::tag: &web_schema::kind_search,
        web_schema::query: query.to_owned(),
        web_schema::provider: provider_name(provider),
        metadata::created_at: created_at,
        web_schema::result*: result_ids,
    };
    Ok(search)
}

fn fetch_fragment(
    provider: Provider,
    url: &str,
    content: &str,
    created_at: Inline<NsTAIInterval>,
) -> Fragment {
    entity! { _ @
        metadata::tag: &web_schema::kind_fetch,
        web_schema::provider: provider_name(provider),
        metadata::created_at: created_at,
        web_schema::url: url.to_owned(),
        web_schema::content: content.to_owned(),
    }
}

fn store_search_if_enabled(
    no_store: bool,
    storage: WebStorage<'_>,
    provider: Provider,
    query: &str,
    results: &[SearchResult],
) -> Result<()> {
    if no_store {
        return Ok(());
    }
    store_search(storage, provider, query, results)
}

fn store_search(
    storage: WebStorage<'_>,
    provider: Provider,
    query: &str,
    results: &[SearchResult],
) -> Result<()> {
    store_search_at(
        storage,
        provider,
        query,
        results,
        epoch_interval(now_epoch()),
    )?;
    Ok(())
}

fn store_search_at(
    storage: WebStorage<'_>,
    provider: Provider,
    query: &str,
    results: &[SearchResult],
    created_at: Inline<NsTAIInterval>,
) -> Result<CollectionCommit> {
    let fragment = search_fragment(provider, query, results, created_at)?;
    storage.publish(fragment, "web search")
}

fn store_fetch_if_enabled(
    no_store: bool,
    storage: WebStorage<'_>,
    provider: Provider,
    url: &str,
    content: &str,
) -> Result<()> {
    if no_store {
        return Ok(());
    }
    store_fetch(storage, provider, url, content)
}

fn store_fetch(
    storage: WebStorage<'_>,
    provider: Provider,
    url: &str,
    content: &str,
) -> Result<()> {
    store_fetch_at(storage, provider, url, content, epoch_interval(now_epoch()))?;
    Ok(())
}

fn store_fetch_at(
    storage: WebStorage<'_>,
    provider: Provider,
    url: &str,
    content: &str,
    created_at: Inline<NsTAIInterval>,
) -> Result<CollectionCommit> {
    let fragment = fetch_fragment(provider, url, content, created_at);
    storage.publish(fragment, "web fetch")
}

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn epoch_interval(epoch: Epoch) -> Inline<NsTAIInterval> {
    (epoch, epoch).try_to_inline().unwrap()
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
    use super::*;

    use std::collections::HashSet;
    use std::fs::File;

    use ed25519_dalek::SigningKey;
    use triblespace::core::collection::{discover_collection_records, simplearchive_union};
    use triblespace::core::repo::{PinStore, Repository};
    use triblespace::macros::{find, pattern};

    fn test_id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn at_unix(seconds: f64) -> Inline<NsTAIInterval> {
        epoch_interval(Epoch::from_unix_seconds(seconds))
    }

    fn fresh_storage(directory: &tempfile::TempDir) -> (PathBuf, PathBuf, Id) {
        let pile = directory.path().join("web.pile");
        let key = directory.path().join("web.key");
        File::create(&pile).unwrap();
        collection_access::initialize_signer(&pile, Some(&key)).unwrap();
        (pile, key, test_id(0x51))
    }

    fn collection_commits(
        pile_path: &Path,
        key_path: &Path,
        scope: Id,
    ) -> (PileReader, Vec<CollectionCommit>) {
        let signer = collection_access::load_signer(pile_path, Some(key_path)).unwrap();
        let definition = simplearchive_union::definition(scope);
        let mut pile = collection_access::open_pile_strict(pile_path).unwrap();
        let reader = pile.reader().unwrap();
        pile.close().unwrap();
        let records = discover_collection_records(&reader).unwrap();
        let commits = records
            .commits()
            .iter()
            .filter(|commit| commit.collection() == definition.id())
            .filter(|commit| commit.public_key().raw == signer.verifying_key().to_bytes())
            .cloned()
            .collect();
        (reader, commits)
    }

    fn sample_results() -> Vec<SearchResult> {
        vec![
            SearchResult {
                url: "https://example.com/one".to_owned(),
                title: Some("One".to_owned()),
                snippet: Some("First result".to_owned()),
            },
            SearchResult {
                url: "https://example.com/two".to_owned(),
                title: Some(String::new()),
                snippet: None,
            },
        ]
    }

    fn legacy_pin(pile_path: &Path, branch: Id) -> Inline<Handle<blobencodings::SimpleArchive>> {
        let mut pile = collection_access::open_pile_strict(pile_path).unwrap();
        let pin = pile.head(branch).unwrap().unwrap();
        pile.close().unwrap();
        pin
    }

    #[test]
    fn search_and_fetch_each_publish_one_self_contained_commit() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key, scope) = fresh_storage(&directory);
        let storage = WebStorage {
            pile: &pile,
            key: Some(&key),
            scope,
        };
        let results = sample_results();
        let search_time = at_unix(10.0);
        let expected_search =
            search_fragment(Provider::Tavily, "rust triplestore", &results, search_time).unwrap();

        let search = store_search_at(
            storage,
            Provider::Tavily,
            "rust triplestore",
            &results,
            search_time,
        )
        .unwrap();

        let signer = collection_access::load_signer(&pile, Some(&key)).unwrap();
        let allowed = HashSet::from([signer.verifying_key()]);
        let view = collection_access::materialize_scope(&pile, scope, &allowed).unwrap();
        assert_eq!(view.facts, expected_search.facts().clone());
        let (reader, commits) = collection_commits(&pile, &key, scope);
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0], search);
        search.verify_strict().unwrap();

        let query = find!(
            (query: Inline<Handle<LongString>>),
            pattern!(&view.facts, [{
                metadata::tag: web_schema::kind_search,
                web_schema::query: ?query,
            }])
        )
        .next()
        .unwrap()
        .0;
        assert_eq!(
            &*view.reader.get::<View<str>, _>(query).unwrap(),
            "rust triplestore"
        );
        let urls: Vec<_> = find!(
            (url: Inline<Handle<LongString>>),
            pattern!(&view.facts, [{
                metadata::tag: web_schema::kind_result,
                web_schema::url: ?url,
            }])
        )
        .map(|(handle,)| view.reader.get::<View<str>, _>(handle).unwrap().to_string())
        .collect();
        assert_eq!(urls.len(), 2);
        assert!(urls.contains(&"https://example.com/one".to_owned()));
        assert!(urls.contains(&"https://example.com/two".to_owned()));

        let metadata_facts: TribleSet = reader.get(search.metadata()).unwrap();
        let description = find!(
            (description: Inline<Handle<LongString>>),
            pattern!(&metadata_facts, [{ metadata::description: ?description }])
        )
        .next()
        .unwrap()
        .0;
        assert_eq!(
            &*reader.get::<View<str>, _>(description).unwrap(),
            "web search"
        );

        let fetch_time = at_unix(20.0);
        let expected_fetch = fetch_fragment(
            Provider::Exa,
            "https://example.com/page",
            "Fetched body",
            fetch_time,
        );
        let fetch = store_fetch_at(
            storage,
            Provider::Exa,
            "https://example.com/page",
            "Fetched body",
            fetch_time,
        )
        .unwrap();

        let view = collection_access::materialize_scope(&pile, scope, &allowed).unwrap();
        let mut expected = expected_search.into_facts();
        expected += expected_fetch.into_facts();
        assert_eq!(view.facts, expected);
        let (_, commits) = collection_commits(&pile, &key, scope);
        assert_eq!(commits.len(), 2);
        assert!(commits.contains(&search));
        assert!(commits.contains(&fetch));
        let content = find!(
            (content: Inline<Handle<LongString>>),
            pattern!(&view.facts, [{
                metadata::tag: web_schema::kind_fetch,
                web_schema::content: ?content,
            }])
        )
        .next()
        .unwrap()
        .0;
        assert_eq!(
            &*view.reader.get::<View<str>, _>(content).unwrap(),
            "Fetched body"
        );
    }

    #[test]
    fn no_store_paths_do_not_require_or_create_a_signer_or_pile() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("must-not-exist.pile");
        let key = directory.path().join("must-not-exist.key");
        let storage = WebStorage {
            pile: &pile,
            key: Some(&key),
            scope: test_id(0x52),
        };

        store_search_if_enabled(
            true,
            storage,
            Provider::Tavily,
            "not sent",
            &sample_results(),
        )
        .unwrap();
        store_fetch_if_enabled(
            true,
            storage,
            Provider::Exa,
            "https://example.com/not-fetched",
            "not stored",
        )
        .unwrap();

        assert!(!pile.exists());
        assert!(!key.exists());
    }

    #[test]
    fn legacy_web_migration_preserves_raw_deltas() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("legacy-web.pile");
        let key_path = directory.path().join("collection.key");
        File::create(&pile_path).unwrap();

        let pile = collection_access::open_pile_strict(&pile_path).unwrap();
        let mut repo =
            Repository::new(pile, SigningKey::from_bytes(&[0x71; 32]), Fragment::empty()).unwrap();
        let web_branch = *repo.create_branch(LEGACY_WEB_BRANCH_NAME, None).unwrap();

        // Deliberately split one logical search across raw historical deltas.
        // Migration must preserve exactly these facts, not rebuild a modern
        // self-contained search fragment per legacy commit.
        let (result_id, result_facts) = {
            let mut workspace = repo.pull(web_branch).unwrap();
            let url = workspace.put("https://example.com/legacy".to_owned());
            let title = workspace.put("Legacy title".to_owned());
            let snippet = workspace.put("Legacy snippet".to_owned());
            let result = entity! { _ @
                metadata::tag: &web_schema::kind_result,
                web_schema::url: url,
                web_schema::title: title,
                web_schema::snippet: snippet,
            };
            let result_id = result.root().unwrap();
            let facts = result.into_facts();
            workspace.commit(facts.clone(), "legacy result delta");
            repo.push(&mut workspace).unwrap();
            (result_id, facts)
        };
        let search_facts = {
            let mut workspace = repo.pull(web_branch).unwrap();
            let query = workspace.put("legacy query".to_owned());
            let search = entity! { _ @
                metadata::tag: &web_schema::kind_search,
                web_schema::query: query,
                web_schema::provider: "tavily",
                metadata::created_at: at_unix(50.0),
                web_schema::result: &result_id,
            }
            .into_facts();
            workspace.commit(search.clone(), "legacy search delta");
            repo.push(&mut workspace).unwrap();
            search
        };
        let fetch_facts = {
            let mut workspace = repo.pull(web_branch).unwrap();
            let url = workspace.put("https://example.com/fetched".to_owned());
            let content = workspace.put("Legacy fetched body".to_owned());
            let fetch = entity! { _ @
                metadata::tag: &web_schema::kind_fetch,
                web_schema::provider: "exa",
                metadata::created_at: at_unix(60.0),
                web_schema::url: url,
                web_schema::content: content,
            }
            .into_facts();
            workspace.commit(fetch.clone(), "legacy fetch delta");
            repo.push(&mut workspace).unwrap();
            fetch
        };

        repo.close().unwrap();

        collection_access::initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let scope = test_id(0x53);
        let storage = WebStorage {
            pile: &pile_path,
            key: Some(&key_path),
            scope,
        };
        let old_pin = legacy_pin(&pile_path, web_branch);
        let mut expected = result_facts;
        expected += search_facts;
        expected += fetch_facts;

        let first = migrate_legacy(storage, None).unwrap();
        let length = std::fs::metadata(&pile_path).unwrap().len();
        let second = migrate_legacy(storage, Some(web_branch)).unwrap();

        assert_eq!(first.commits.len(), 3);
        assert_eq!(first.commits, second.commits);
        assert_eq!(first.facts, expected.len() as usize);
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), length);
        assert_eq!(legacy_pin(&pile_path, web_branch), old_pin);

        let signer = collection_access::load_signer(&pile_path, Some(&key_path)).unwrap();
        let allowed = HashSet::from([signer.verifying_key()]);
        let view = collection_access::materialize_scope(&pile_path, scope, &allowed).unwrap();
        assert_eq!(view.facts, expected);
        preflight_legacy_web_payloads(&view.reader, &view.facts).unwrap();
    }

    #[test]
    fn empty_legacy_web_branch_is_a_zero_commit_noop() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("empty-legacy-web.pile");
        let key_path = directory.path().join("collection.key");
        File::create(&pile_path).unwrap();

        let pile = collection_access::open_pile_strict(&pile_path).unwrap();
        let mut repo =
            Repository::new(pile, SigningKey::from_bytes(&[0x72; 32]), Fragment::empty()).unwrap();
        let branch = *repo.create_branch(LEGACY_WEB_BRANCH_NAME, None).unwrap();
        repo.close().unwrap();
        collection_access::initialize_signer(&pile_path, Some(&key_path)).unwrap();

        let pin = legacy_pin(&pile_path, branch);
        let length = std::fs::metadata(&pile_path).unwrap().len();
        // Exercise the real dispatch path without any provider credentials or
        // config branch: migration is storage maintenance, not a web request.
        let cli = Cli::try_parse_from([
            "web".to_owned(),
            "--pile".to_owned(),
            pile_path.display().to_string(),
            "--key".to_owned(),
            key_path.display().to_string(),
            "--scope".to_owned(),
            format!("{:x}", test_id(0x54)),
            "migrate-legacy".to_owned(),
        ])
        .unwrap();
        run(cli).unwrap();
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), length);

        let report = migrate_legacy(
            WebStorage {
                pile: &pile_path,
                key: Some(&key_path),
                scope: test_id(0x54),
            },
            None,
        )
        .unwrap();

        assert_eq!(report.branch_id, branch);
        assert!(report.head.is_none());
        assert!(report.commits.is_empty());
        assert_eq!(report.facts, 0);
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), length);
        assert_eq!(legacy_pin(&pile_path, branch), pin);
    }

    #[test]
    fn legacy_web_preflight_strictly_reads_direct_longstring_handles() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("missing-web-payload.pile");
        File::create(&pile_path).unwrap();
        let mut pile = collection_access::open_pile_strict(&pile_path).unwrap();
        let reader = pile.reader().unwrap();
        pile.close().unwrap();

        let missing: Inline<Handle<LongString>> = Inline::new([0x91; 32]);
        let entity = ufoid();
        let facts = entity! { &entity @ web_schema::snippet: missing }.into_facts();
        let error = preflight_legacy_web_payloads(&reader, &facts).unwrap_err();
        assert!(format!("{error:#}").contains("legacy web::snippet payload"));
    }

    #[test]
    fn search_identity_remains_orderless_deduplicated_and_ignores_empty_optionals() {
        let created = at_unix(30.0);
        let first = SearchResult {
            url: "https://example.com/a".to_owned(),
            title: Some(String::new()),
            snippet: None,
        };
        let second = SearchResult {
            url: "https://example.com/b".to_owned(),
            title: Some("B".to_owned()),
            snippet: Some("second".to_owned()),
        };
        let forward = search_fragment(
            Provider::Tavily,
            "same identity",
            &[first.clone(), second.clone()],
            created,
        )
        .unwrap();
        let reverse = search_fragment(
            Provider::Tavily,
            "same identity",
            &[second, first.clone()],
            created,
        )
        .unwrap();
        let duplicate = search_fragment(
            Provider::Tavily,
            "same identity",
            &[first.clone(), first],
            created,
        )
        .unwrap();
        let single = search_fragment(
            Provider::Tavily,
            "same identity",
            &[SearchResult {
                url: "https://example.com/a".to_owned(),
                title: None,
                snippet: None,
            }],
            created,
        )
        .unwrap();

        assert_eq!(forward, reverse);
        assert_eq!(duplicate, single);
    }

    #[test]
    fn headspace_agreement_resolves_and_divergence_remains_a_fork() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("config.pile");
        File::create(&pile_path).unwrap();
        collection_access::initialize_signer(&pile_path, None).unwrap();
        let anchor = test_id(0x61);
        let profile = headspace::default_profile(anchor, "web");
        let mut genesis = headspace::default_config(anchor);
        genesis.tavily_api_key = Some("genesis-tavily".to_owned());
        genesis.exa_api_key = Some("genesis-exa".to_owned());
        let (fragment, _, genesis_id) =
            headspace::add_profile_fragment(&profile, &genesis, &[]).unwrap();
        collection_access::publish_fragment(
            &pile_path,
            None,
            HEADSPACE_SCOPE_ID,
            fragment,
            Fragment::empty(),
        )
        .unwrap();

        let mut left = genesis.clone();
        left.tavily_api_key = Some("left-tavily".to_owned());
        let mut right = genesis.clone();
        right.tavily_api_key = Some("right-tavily".to_owned());
        let (left, left_id) = headspace::config_snapshot_fragment(&left, &[genesis_id]).unwrap();
        let (right, right_id) = headspace::config_snapshot_fragment(&right, &[genesis_id]).unwrap();
        for fragment in [left, right] {
            collection_access::publish_fragment(
                &pile_path,
                None,
                HEADSPACE_SCOPE_ID,
                fragment,
                Fragment::empty(),
            )
            .unwrap();
        }

        let mut agreed = genesis.clone();
        agreed.tavily_api_key = Some("agreed-tavily".to_owned());
        agreed.exa_api_key = Some("agreed-exa".to_owned());
        let (first, first_id) = headspace::config_snapshot_fragment(&agreed, &[left_id]).unwrap();
        let (second, _) = headspace::config_snapshot_fragment(&agreed, &[right_id]).unwrap();
        for fragment in [first, second] {
            collection_access::publish_fragment(
                &pile_path,
                None,
                HEADSPACE_SCOPE_ID,
                fragment,
                Fragment::empty(),
            )
            .unwrap();
        }

        let snapshot = load_config_snapshot(&pile_path, None).unwrap();
        assert_eq!(snapshot.tavily_api_key.as_deref(), Some("agreed-tavily"));
        assert_eq!(snapshot.exa_api_key.as_deref(), Some("agreed-exa"));

        let mut divergent = agreed;
        divergent.tavily_api_key = Some("forked-tavily".to_owned());
        let (fragment, _) = headspace::config_snapshot_fragment(&divergent, &[first_id]).unwrap();
        collection_access::publish_fragment(
            &pile_path,
            None,
            HEADSPACE_SCOPE_ID,
            fragment,
            Fragment::empty(),
        )
        .unwrap();
        let error = match load_config_snapshot(&pile_path, None) {
            Ok(_) => panic!("divergent Headspace config unexpectedly resolved"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("forked"));
    }

    #[test]
    fn missing_headspace_track_returns_defaults_without_appending() {
        let directory = tempfile::tempdir().unwrap();
        let empty = directory.path().join("empty.pile");
        File::create(&empty).unwrap();
        collection_access::initialize_signer(&empty, None).unwrap();
        let empty_length = std::fs::metadata(&empty).unwrap().len();
        let snapshot = load_config_snapshot(&empty, None).unwrap();
        assert!(snapshot.tavily_api_key.is_none());
        assert!(snapshot.exa_api_key.is_none());
        assert_eq!(std::fs::metadata(&empty).unwrap().len(), empty_length);
    }
}
