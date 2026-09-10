use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::clock;
use crate::collection_names::open_configured;
use crate::schemas::headspace::{
    playground_config, DEFAULT_SCOPE_ID as HEADSPACE_SCOPE_ID, KIND_CONFIG_ID, KIND_LIVE_RECORD,
};
use crate::schemas::web::{web_schema, DEFAULT_SCOPE_ID};
use crate::secrets::{storage as secret_storage, SecretsSnapshot};
#[cfg(test)]
use crate::storage::load_signer;
use crate::storage::{open_secrets_collection_read, FactArchive};
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::json;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::{CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::SnapshotSource;
use triblespace::macros::{find, pattern};
use triblespace::prelude::inlineencodings::NsTAIInterval;
use triblespace::prelude::*;

#[derive(Clone, Default)]
pub struct ApiKeys {
    pub tavily: Option<String>,
    pub exa: Option<String>,
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    #[default]
    Auto,
    Tavily,
    Exa,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchResult {
    pub url: String,
    pub title: Option<String>,
    pub snippet: Option<String>,
}
#[derive(Clone, Debug)]
pub struct SearchReport {
    pub provider: Provider,
    pub query: String,
    pub results: Vec<SearchResult>,
    pub observed_at: Inline<NsTAIInterval>,
}
#[derive(Clone, Debug)]
pub struct FetchReport {
    pub provider: Provider,
    pub url: String,
    pub content: String,
    pub observed_at: Inline<NsTAIInterval>,
}

/// Trusted launcher configuration, never exposed as MCP tool arguments.
#[derive(Clone, Debug)]
pub struct Endpoints {
    pub tavily: String,
    pub exa: String,
}
impl Default for Endpoints {
    fn default() -> Self {
        Self {
            tavily: "https://api.tavily.com".into(),
            exa: "https://api.exa.ai".into(),
        }
    }
}
impl std::fmt::Debug for ApiKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeys")
            .field("tavily_configured", &self.tavily.is_some())
            .field("exa_configured", &self.exa.is_some())
            .finish()
    }
}
/// Network observations and native recording are distinct direct operations.
/// Frontends preserve display-before-recording: a failed emission does not
/// issue the HTTP request again or publish a second observation.
#[derive(Clone, Debug)]
pub struct Web {
    storage: crate::storage::Storage,
    keys: ApiKeys,
    endpoints: Endpoints,
}
impl Web {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self {
            storage,
            keys: ApiKeys::default(),
            endpoints: Endpoints::default(),
        }
    }
    pub fn with_api_keys(mut self, keys: ApiKeys) -> Self {
        self.keys = keys;
        self
    }
    pub fn with_endpoints(mut self, endpoints: Endpoints) -> Self {
        self.endpoints = endpoints;
        self
    }
    fn storage(&self) -> WebStorage<'_> {
        WebStorage {
            storage: &self.storage,
        }
    }
    fn resolve_keys(&self, provider: Provider) -> Result<ApiKeys> {
        let mut keys = self.keys.clone();
        let needs_headspace = match provider {
            Provider::Auto => keys.tavily.is_none() || keys.exa.is_none(),
            Provider::Tavily => keys.tavily.is_none(),
            Provider::Exa => keys.exa.is_none(),
        };
        if needs_headspace {
            let configured = self.storage().open_web_secrets()?;
            keys.tavily = keys.tavily.or(configured.tavily);
            keys.exa = keys.exa.or(configured.exa);
        }
        Ok(keys)
    }
    fn client(&self) -> Result<Client> {
        Client::builder()
            .user_agent("playground-web-faculty/0")
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .context("build http client")
    }
    pub fn search(
        &self,
        provider: Provider,
        query: &str,
        max_results: usize,
    ) -> Result<SearchReport> {
        let keys = self.resolve_keys(provider)?;
        let provider = choose_provider(provider, &keys)?;
        let client = self.client()?;
        let results = match provider {
            Provider::Tavily => tavily_search(
                &client,
                &self.endpoints.tavily,
                keys.tavily.as_deref().unwrap(),
                query,
                max_results,
            )?,
            Provider::Exa => exa_search(
                &client,
                &self.endpoints.exa,
                keys.exa.as_deref().unwrap(),
                query,
                max_results,
            )?,
            Provider::Auto => unreachable!("provider is resolved"),
        };
        Ok(SearchReport {
            provider,
            query: query.into(),
            results,
            observed_at: clock::point_now()?,
        })
    }
    pub fn fetch(
        &self,
        provider: Provider,
        url: &str,
        max_characters: usize,
    ) -> Result<FetchReport> {
        let keys = self.resolve_keys(provider)?;
        let provider = choose_provider_fetch(provider, &keys)?;
        let client = self.client()?;
        let content = match provider {
            Provider::Tavily => tavily_extract(
                &client,
                &self.endpoints.tavily,
                keys.tavily.as_deref().unwrap(),
                url,
            )?,
            Provider::Exa => exa_contents(
                &client,
                &self.endpoints.exa,
                keys.exa.as_deref().unwrap(),
                url,
                max_characters,
            )?,
            Provider::Auto => unreachable!("provider is resolved"),
        };
        Ok(FetchReport {
            provider,
            url: url.into(),
            content,
            observed_at: clock::point_now()?,
        })
    }
    pub fn record_search(&self, report: &SearchReport) -> Result<()> {
        self.storage().store(
            search_fragment(
                report.provider,
                &report.query,
                &report.results,
                report.observed_at,
            )?,
            "web search observation",
        )
    }
    pub fn record_fetch(&self, report: &FetchReport) -> Result<()> {
        self.storage().store(
            fetch_fragment(
                report.provider,
                &report.url,
                &report.content,
                report.observed_at,
            ),
            "web fetch observation",
        )
    }
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
    storage: &'a crate::storage::Storage,
}

impl WebStorage<'_> {
    /// Resolve Headspace once and decrypt exactly the credential versions it
    /// names. Labels and timestamps never participate in runtime selection.
    fn open_web_secrets(&self) -> Result<ApiKeys> {
        self.storage.with_pile(|pile, signer| {
            let result = pollster::block_on(async {
                let source = open_configured(pile, HEADSPACE_SCOPE_ID, signer.verifying_key())?;
                let descriptor_snapshot = pile.snapshot()?;
                let policy = source.policy(&descriptor_snapshot)?;
                drop(descriptor_snapshot);
                let headspace_succinct =
                    pile.derive::<SuccinctArchiveBlob>(source, (), policy.clone())?;
                let headspace_rank9 = pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(
                    headspace_succinct,
                    (),
                    policy,
                )?;

                let secrets_collection =
                    open_secrets_collection_read(pile, signer.verifying_key())?;
                for (label, source) in [
                    ("Headspace", source),
                    ("Secrets", secrets_collection.source()),
                ] {
                    drop(
                        pile.ensure(source)
                            .await
                            .with_context(|| format!("ensure {label} source collection"))?,
                    );
                }
                let before = pile
                    .snapshot()
                    .context("freeze shared Web credential support snapshot")?;
                let secrets_support = secrets_collection
                    .source()
                    .admitted(&before)
                    .context("admit Secrets collection support")?;
                drop(before);
                drop(
                    pile.maintain(headspace_succinct)
                        .await
                        .context("maintain Headspace fact collection")?,
                );
                drop(
                    pile.maintain(headspace_rank9)
                        .await
                        .context("maintain Headspace fact collection")?,
                );

                let store_snapshot = secrets_collection
                    .ensure_exact(pile, &secrets_support)
                    .await
                    .context("ensure configured Secrets collection")?;
                let secrets = secret_storage::snapshot_exact(
                    store_snapshot,
                    secrets_collection,
                    secrets_support,
                )
                .context("attach exact Secrets collection")?;

                // Observe Headspace and Secrets through one final immutable pile
                // snapshot, then project only the facts Web actually consumes.
                let reader = secrets.store_snapshot();
                let facts = reader
                    .collection(headspace_rank9)
                    .context("attach maintained Headspace collection")?
                    .view::<FactArchive>()
                    .context("read maintained Headspace collection")?;
                let versions = web_secret_versions(&facts)?;

                Ok(ApiKeys {
                    tavily: open_web_secret(&secrets, signer, &versions.tavily, "Tavily")?,
                    exa: open_web_secret(&secrets, signer, &versions.exa, "Exa")?,
                })
            });
            result
        })
    }

    fn store(&self, mut fragment: Fragment, description: &'static str) -> Result<()> {
        self.storage.with_pile(|pile, signer| {
            fragment.describe_with(entity! { metadata::description: description });
            let result = (|| {
                let collection = open_configured(pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
                pile.commit(collection, signer, fragment)
                    .context("commit Web observation")
                    .map(|_| ())
            })();
            result
        })
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
    secrets: &SecretsSnapshot<triblespace::core::repo::pile::PileSnapshot>,
    signer: &SigningKey,
    versions: &BTreeSet<Id>,
    role: &str,
) -> Result<Option<String>> {
    let mut failures = Vec::new();
    for version in versions {
        match secrets.open(*version, signer) {
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
    base: &str,
    api_key: &str,
    query: &str,
    max_results: usize,
) -> Result<Vec<SearchResult>> {
    let resp: TavilySearchResponse = client
        .post(format!("{}/{}", base.trim_end_matches('/'), "search"))
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

fn tavily_extract(client: &Client, base: &str, api_key: &str, url: &str) -> Result<String> {
    let resp: TavilyExtractResponse = client
        .post(format!("{}/{}", base.trim_end_matches('/'), "extract"))
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
    base: &str,
    api_key: &str,
    query: &str,
    max_results: usize,
) -> Result<Vec<SearchResult>> {
    let resp: ExaSearchResponse = client
        .post(format!("{}/{}", base.trim_end_matches('/'), "search"))
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
    base: &str,
    api_key: &str,
    url: &str,
    max_characters: usize,
) -> Result<String> {
    let resp: ExaContentsResponse = client
        .post(format!("{}/{}", base.trim_end_matches('/'), "contents"))
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

#[cfg(test)]
mod tests {
    use std::fs::File;

    use hifitime::Epoch;

    use super::*;
    use crate::storage::{initialize_signer, open_pile_strict};
    use crate::web::cli::Cli;
    use clap::CommandFactory;

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
        let keys = Web::new(missing, None)
            .with_api_keys(ApiKeys {
                tavily: Some("explicit-tavily-key".into()),
                exa: None,
            })
            .resolve_keys(Provider::Tavily)
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
            storage: &crate::storage::Storage::new(pile_path.clone(), Some(key_path.clone())),
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
            crate::collection_names::open(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())
                .unwrap();
        let descriptor_snapshot = pile.snapshot().unwrap();
        let policy = source.policy(&descriptor_snapshot).unwrap();
        drop(descriptor_snapshot);
        let collection_succinct = pile
            .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
            .unwrap();
        let collection_rank9 = pile
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(collection_succinct, (), policy)
            .unwrap();
        let store_snapshot = pollster::block_on(async {
            drop(pile.ensure(source).await?);
            drop(pile.maintain(collection_succinct).await?);
            pile.maintain(collection_rank9).await
        })
        .unwrap();
        let facts = store_snapshot
            .collection(collection_rank9)
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
