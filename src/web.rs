//! Web providers, observations, and the Web side of the egress boundary.
//!
//! Everything that actually talks to Tavily or Exa lives behind [`Backend`].
//! That trait is the whole network surface of this faculty, which makes two
//! things possible at once: the broker in [`crate::egress`] can drive it
//! without knowing anything about HTTP, and tests can drive the entire
//! request → serve → result round trip with a stub that opens no socket.
//!
//! The observation fragments are shared by both paths on purpose. A page
//! fetched directly by a window that has network and keys, and the same page
//! fetched on behalf of a sandboxed mind, leave the *same*
//! `web_schema::kind_fetch` entity in the same collection. Every existing
//! query over Web keeps working, and "everything this mind fetched, ever"
//! does not have to union two shapes.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::json;
use triblespace::core::metadata;
use triblespace::core::repo::SnapshotSource;
use triblespace::macros::entity;
use triblespace::prelude::*;

use crate::egress::{Crossing, Handler, IntervalValue, Refusal, RequestRecord};
use crate::headspace;
use crate::legacy_hint::open_scope;
#[cfg(test)]
use crate::schemas::egress::request;
use crate::schemas::headspace::DEFAULT_SCOPE_ID as HEADSPACE_SCOPE_ID;
use crate::schemas::web::{web_schema, DEFAULT_SCOPE_ID, OPERATION_FETCH, OPERATION_SEARCH};
use crate::secrets::storage as vaults;
use crate::storage::{load_signer, open_pile_strict, read_fact_collection};

/// Parameter names a Web egress request may carry.
///
/// String-valued, because the ledger stays legible without Web's vocabulary
/// loaded and a value the handler cannot parse becomes a recorded
/// [`Denial::Malformed`] rather than a silent default.
pub const PARAM_PROVIDER: &str = "provider";
pub const PARAM_MAX_RESULTS: &str = "max-results";
pub const PARAM_MAX_CHARACTERS: &str = "max-characters";

pub const DEFAULT_MAX_RESULTS: usize = 5;
pub const DEFAULT_MAX_CHARACTERS: usize = 12_000;

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    Auto,
    Tavily,
    Exa,
}

impl Provider {
    pub fn name(self) -> &'static str {
        match self {
            Self::Tavily => "tavily",
            Self::Exa => "exa",
            Self::Auto => "auto",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "tavily" => Some(Self::Tavily),
            "exa" => Some(Self::Exa),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ApiKeys {
    pub tavily: Option<String>,
    pub exa: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SearchResult {
    pub url: String,
    pub title: Option<String>,
    pub snippet: Option<String>,
}

/// The one place Web crosses the network.
///
/// Implementors hold whatever credentials the crossing needs. Nothing above
/// this trait ever sees them, which is why the requesting side of the split
/// can run with no vault at all.
pub trait Backend {
    /// Whether this backend can serve a concrete provider at all.
    fn serves(&self, provider: Provider) -> bool;

    fn search(
        &self,
        provider: Provider,
        query: &str,
        max_results: usize,
    ) -> std::result::Result<Vec<SearchResult>, Refusal>;

    fn fetch(
        &self,
        provider: Provider,
        url: &str,
        max_characters: usize,
    ) -> std::result::Result<String, Refusal>;
}

/// Resolve `Auto` against what the backend can actually serve, and refuse
/// rather than substitute when an explicit provider has no credential.
pub fn choose_provider(
    requested: Provider,
    backend: &dyn Backend,
) -> std::result::Result<Provider, Refusal> {
    match requested {
        Provider::Tavily | Provider::Exa => {
            if backend.serves(requested) {
                Ok(requested)
            } else {
                Err(Refusal::policy(format!(
                    "no {name} credential available (attach an exact Headspace secret \
                     or pass --{name}-api-key)",
                    name = requested.name()
                )))
            }
        }
        Provider::Auto => {
            if backend.serves(Provider::Tavily) {
                Ok(Provider::Tavily)
            } else if backend.serves(Provider::Exa) {
                Ok(Provider::Exa)
            } else {
                Err(Refusal::policy(
                    "no Web provider credential is referenced by Headspace or explicitly \
                     supplied (pass --tavily-api-key or --exa-api-key)",
                ))
            }
        }
    }
}

/// Fetch prefers Exa, which returns cleaner extracted text.
pub fn choose_provider_fetch(
    requested: Provider,
    backend: &dyn Backend,
) -> std::result::Result<Provider, Refusal> {
    match requested {
        Provider::Auto => {
            if backend.serves(Provider::Exa) {
                Ok(Provider::Exa)
            } else if backend.serves(Provider::Tavily) {
                Ok(Provider::Tavily)
            } else {
                Err(Refusal::policy(
                    "no Web provider credential is referenced by Headspace or explicitly \
                     supplied (pass --tavily-api-key or --exa-api-key)",
                ))
            }
        }
        other => choose_provider(other, backend),
    }
}

/// The real network backend. Constructing one requires the keys; the broker
/// is the only process that does.
pub struct LiveBackend {
    client: Client,
    keys: ApiKeys,
}

impl LiveBackend {
    pub fn new(keys: ApiKeys) -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                .user_agent("playground-web-faculty/0")
                .build()
                .context("build http client")?,
            keys,
        })
    }
}

impl Backend for LiveBackend {
    fn serves(&self, provider: Provider) -> bool {
        match provider {
            Provider::Tavily => self.keys.tavily.is_some(),
            Provider::Exa => self.keys.exa.is_some(),
            Provider::Auto => self.keys.tavily.is_some() || self.keys.exa.is_some(),
        }
    }

    fn search(
        &self,
        provider: Provider,
        query: &str,
        max_results: usize,
    ) -> std::result::Result<Vec<SearchResult>, Refusal> {
        match provider {
            Provider::Tavily => tavily_search(
                &self.client,
                self.keys.tavily.as_deref().unwrap_or_default(),
                query,
                max_results,
            ),
            Provider::Exa => exa_search(
                &self.client,
                self.keys.exa.as_deref().unwrap_or_default(),
                query,
                max_results,
            ),
            Provider::Auto => Err(Refusal::malformed("provider was not resolved before use")),
        }
    }

    fn fetch(
        &self,
        provider: Provider,
        url: &str,
        max_characters: usize,
    ) -> std::result::Result<String, Refusal> {
        match provider {
            Provider::Tavily => tavily_extract(
                &self.client,
                self.keys.tavily.as_deref().unwrap_or_default(),
                url,
            ),
            Provider::Exa => exa_contents(
                &self.client,
                self.keys.exa.as_deref().unwrap_or_default(),
                url,
                max_characters,
            ),
            Provider::Auto => Err(Refusal::malformed("provider was not resolved before use")),
        }
    }
}

/// Classify one provider failure so the ledger can sort refusals without
/// reading prose. Rate and budget rejections are their own category because
/// "they are throttling us" and "the page is broken" want different responses.
fn classify(error: reqwest::Error, what: &str) -> Refusal {
    let quota = error
        .status()
        .is_some_and(|status| status.as_u16() == 402 || status.as_u16() == 429);
    let reason = format!("{what}: {error}");
    if quota {
        Refusal::quota(reason)
    } else {
        Refusal::provider_error(reason)
    }
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
) -> std::result::Result<Vec<SearchResult>, Refusal> {
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
        .map_err(|error| classify(error, "tavily search request"))?
        .error_for_status()
        .map_err(|error| classify(error, "tavily search status"))?
        .json()
        .map_err(|error| classify(error, "tavily search json"))?;

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

fn tavily_extract(
    client: &Client,
    api_key: &str,
    url: &str,
) -> std::result::Result<String, Refusal> {
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
        .map_err(|error| classify(error, "tavily extract request"))?
        .error_for_status()
        .map_err(|error| classify(error, "tavily extract status"))?
        .json()
        .map_err(|error| classify(error, "tavily extract json"))?;

    let Some(first) = resp.results.into_iter().next() else {
        return Err(Refusal::provider_error(
            "tavily extract returned no results",
        ));
    };
    Ok(if first.raw_content.is_empty() {
        first.content
    } else {
        first.raw_content
    })
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
) -> std::result::Result<Vec<SearchResult>, Refusal> {
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
        .map_err(|error| classify(error, "exa search request"))?
        .error_for_status()
        .map_err(|error| classify(error, "exa search status"))?
        .json()
        .map_err(|error| classify(error, "exa search json"))?;

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
) -> std::result::Result<String, Refusal> {
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
        .map_err(|error| classify(error, "exa contents request"))?
        .error_for_status()
        .map_err(|error| classify(error, "exa contents status"))?
        .json()
        .map_err(|error| classify(error, "exa contents json"))?;

    let Some(first) = resp.results.into_iter().next() else {
        return Err(Refusal::provider_error("exa contents returned no results"));
    };
    Ok(first.text)
}

// --- Observations ---

/// One search observation and the id of its root entity.
pub fn search_fragment(
    provider: Provider,
    query: &str,
    results: &[SearchResult],
    observed_at: IntervalValue,
) -> Result<(Fragment, Id)> {
    let mut fragment = Fragment::empty();
    let query_handle = fragment.put::<blobencodings::UTF8String, _>(query.to_owned());
    let mut result_ids = Vec::with_capacity(results.len());

    for result in results {
        let url_handle = fragment.put::<blobencodings::UTF8String, _>(result.url.clone());
        let title_handle = result
            .title
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| fragment.put::<blobencodings::UTF8String, _>(value.to_owned()));
        let snippet_handle = result
            .snippet
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| fragment.put::<blobencodings::UTF8String, _>(value.to_owned()));
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

    let core = entity! { _ @
        metadata::tag: &web_schema::kind_search,
        web_schema::query: query_handle,
        web_schema::provider: provider.name(),
        metadata::created_at: observed_at,
        web_schema::result*: result_ids,
    };
    let id = core
        .root()
        .ok_or_else(|| anyhow!("Web search fragment has no intrinsic root"))?;
    fragment += core;
    Ok((fragment, id))
}

/// One fetch observation and the id of its root entity.
pub fn fetch_fragment(
    provider: Provider,
    url: &str,
    content: &str,
    observed_at: IntervalValue,
) -> Result<(Fragment, Id)> {
    let mut fragment = Fragment::empty();
    let url_handle = fragment.put::<blobencodings::UTF8String, _>(url.to_owned());
    let content_handle = fragment.put::<blobencodings::UTF8String, _>(content.to_owned());
    let core = entity! { _ @
        metadata::tag: &web_schema::kind_fetch,
        web_schema::provider: provider.name(),
        metadata::created_at: observed_at,
        web_schema::url: url_handle,
        web_schema::content: content_handle,
    };
    let id = core
        .root()
        .ok_or_else(|| anyhow!("Web fetch fragment has no intrinsic root"))?;
    fragment += core;
    Ok((fragment, id))
}

// --- Egress policy and handler ---

/// What this broker will let through.
///
/// Deliberately small and deliberately real: an empty allow list means "any
/// host", a non-empty one means "only these", and a deny entry always wins.
/// Host matching is exact or a dot-suffix, so `example.test` covers
/// `docs.example.test` and never `notexample.test`.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub allow_hosts: Vec<String>,
    pub deny_hosts: Vec<String>,
}

impl Policy {
    /// Scheme and host of an absolute http(s) URL, or a refusal saying why it
    /// is not one. Anything unparseable is refused rather than guessed at.
    fn host_of(url: &str) -> std::result::Result<String, Refusal> {
        let rest = match url.split_once("://") {
            Some(("http", rest)) | Some(("https", rest)) => rest,
            Some((scheme, _)) => {
                return Err(Refusal::malformed(format!(
                    "only http and https may be fetched, not '{scheme}'"
                )))
            }
            None => {
                return Err(Refusal::malformed(
                    "fetch target is not an absolute http(s) URL",
                ))
            }
        };
        let authority = rest
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default()
            .rsplit('@')
            .next()
            .unwrap_or_default();
        let host = authority
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(authority)
            .trim_matches(['[', ']'])
            .to_ascii_lowercase();
        if host.is_empty() {
            return Err(Refusal::malformed("fetch target has no host"));
        }
        Ok(host)
    }

    fn matches(host: &str, rule: &str) -> bool {
        let rule = rule.trim().trim_start_matches('.').to_ascii_lowercase();
        !rule.is_empty() && (host == rule || host.ends_with(&format!(".{rule}")))
    }

    /// Refuse a URL this broker will not fetch, with the reason recorded.
    pub fn check_url(&self, url: &str) -> std::result::Result<(), Refusal> {
        let host = Self::host_of(url)?;
        if self
            .deny_hosts
            .iter()
            .any(|rule| Self::matches(&host, rule))
        {
            return Err(Refusal::policy(format!(
                "host '{host}' is on this broker's deny list"
            )));
        }
        if !self.allow_hosts.is_empty()
            && !self
                .allow_hosts
                .iter()
                .any(|rule| Self::matches(&host, rule))
        {
            return Err(Refusal::policy(format!(
                "host '{host}' is not on this broker's allow list"
            )));
        }
        Ok(())
    }
}

/// The Web side of the broker: policy, then provider, then observation.
pub struct WebHandler<B: Backend> {
    backend: B,
    policy: Policy,
    now: fn() -> Result<IntervalValue>,
}

impl<B: Backend> WebHandler<B> {
    pub fn new(backend: B, policy: Policy) -> Self {
        Self {
            backend,
            policy,
            now: crate::clock::point_now,
        }
    }

    /// Override the clock. Tests pin it so a round trip is reproducible.
    pub fn with_clock(mut self, now: fn() -> Result<IntervalValue>) -> Self {
        self.now = now;
        self
    }
}

impl<B: Backend> Handler for WebHandler<B> {
    fn faculty(&self) -> Id {
        DEFAULT_SCOPE_ID
    }

    fn perform(&self, request: &RequestRecord) -> std::result::Result<Crossing, Refusal> {
        if request.target.trim().is_empty() {
            return Err(Refusal::malformed("request target is empty"));
        }
        let requested = match request.parameter(PARAM_PROVIDER) {
            None => Provider::Auto,
            Some(raw) => Provider::parse(raw).ok_or_else(|| {
                Refusal::malformed(format!(
                    "parameter 'provider' value '{raw}' is not a provider"
                ))
            })?,
        };
        let now = (self.now)().map_err(|error| {
            Refusal::provider_error(format!("read clock before recording crossing: {error}"))
        })?;

        if request.operation == OPERATION_SEARCH {
            let max_results = request.parsed(PARAM_MAX_RESULTS, DEFAULT_MAX_RESULTS)?;
            let provider = choose_provider(requested, &self.backend)?;
            let results = self
                .backend
                .search(provider, &request.target, max_results)?;
            let (fragment, observation) = search_fragment(provider, &request.target, &results, now)
                .map_err(|error| {
                    Refusal::provider_error(format!("build search observation: {error}"))
                })?;
            Ok(Crossing {
                fragment,
                observation,
                description: "web search observation",
            })
        } else if request.operation == OPERATION_FETCH {
            let max_characters = request.parsed(PARAM_MAX_CHARACTERS, DEFAULT_MAX_CHARACTERS)?;
            self.policy.check_url(&request.target)?;
            let provider = choose_provider_fetch(requested, &self.backend)?;
            let content = self
                .backend
                .fetch(provider, &request.target, max_characters)?;
            let (fragment, observation) = fetch_fragment(provider, &request.target, &content, now)
                .map_err(|error| {
                    Refusal::provider_error(format!("build fetch observation: {error}"))
                })?;
            Ok(Crossing {
                fragment,
                observation,
                description: "web fetch observation",
            })
        } else {
            Err(Refusal::malformed(format!(
                "operation {:X} is not a Web operation",
                request.operation
            )))
        }
    }
}

/// The Web operation for a request kind name, for the requesting CLI.
pub fn operation(kind: &str) -> Result<Id> {
    match kind {
        "search" => Ok(OPERATION_SEARCH),
        "fetch" => Ok(OPERATION_FETCH),
        other => bail!("unknown Web request kind '{other}'"),
    }
}

/// The request kind name for a Web operation, for display.
pub fn operation_name(operation: Id) -> &'static str {
    if operation == OPERATION_SEARCH {
        "search"
    } else if operation == OPERATION_FETCH {
        "fetch"
    } else {
        "unknown"
    }
}

/// Resolve Headspace once and decrypt exactly the credential versions it
/// names. Labels and timestamps never participate in runtime selection.
///
/// This is the function the sandboxed side must never need, and does not: it
/// is called by the direct `search`/`fetch` fast path and by the broker, and
/// by nothing on the `request`/`result` path.
pub fn open_web_secrets(pile_path: &Path, key_path: Option<&Path>) -> Result<ApiKeys> {
    let signer = load_signer(pile_path, key_path)?;
    let mut pile = open_pile_strict(pile_path)?;
    let result = (|| {
        let collection = open_scope(&mut pile, HEADSPACE_SCOPE_ID, &signer)?;
        let snapshot = pile.snapshot().context("freeze Headspace store snapshot")?;
        let (facts, _) = read_fact_collection(collection, &snapshot)
            .context("materialize Headspace collection")?;
        let secrets = vaults::discover_local_vaults(&mut pile, &signer)
            .context("discover readable Secrets vaults")?;
        let catalog = headspace::project_result(&snapshot, &facts)
            .context("validate Headspace collection")?;
        headspace::validate_secret_references(&catalog, secrets.snapshot())
            .context("validate exact Headspace credential references")?;
        let (config, _) = headspace::settled_active(&catalog)
            .context("resolve active Headspace configuration")?;
        if config.tavily_secret_version.is_none() && config.exa_secret_version.is_none() {
            return Ok(ApiKeys::default());
        }
        let opened = headspace::open_active_secrets(&catalog, secrets.snapshot(), &signer)?;
        Ok(ApiKeys {
            tavily: opened.tavily_api_key,
            exa: opened.exa_api_key,
        })
    })();
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close Web pile after credential read")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Web pile after credential read also failed: {close_error}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::egress::Denial;

    #[test]
    fn only_absolute_http_urls_are_fetchable() {
        let policy = Policy::default();
        assert!(policy.check_url("https://example.test/a").is_ok());
        assert!(policy.check_url("http://example.test").is_ok());
        assert_eq!(
            policy.check_url("file:///etc/passwd").unwrap_err().denial,
            Denial::Malformed
        );
        assert_eq!(
            policy.check_url("example.test/a").unwrap_err().denial,
            Denial::Malformed
        );
    }

    #[test]
    fn host_rules_match_exactly_or_by_dot_suffix() {
        let policy = Policy {
            allow_hosts: vec!["example.test".to_owned()],
            deny_hosts: vec!["secret.example.test".to_owned()],
        };
        assert!(policy.check_url("https://example.test/a").is_ok());
        assert!(policy.check_url("https://docs.example.test:8443/a").is_ok());
        assert_eq!(
            policy
                .check_url("https://notexample.test/a")
                .unwrap_err()
                .denial,
            Denial::Policy
        );
        assert_eq!(
            policy
                .check_url("https://secret.example.test/a")
                .unwrap_err()
                .denial,
            Denial::Policy
        );
    }
}

/// Offline end-to-end tests of the brokered path.
///
/// Every one of these drives the *whole* boundary — request written to a pile,
/// broker sweep, response read back — with [`Backend`] stubbed. No socket is
/// opened and no vault is read, which is the same property the sandboxed side
/// depends on in production.
#[cfg(test)]
mod broker_tests {
    use super::*;

    use std::fs::File;
    use std::path::PathBuf;

    use hifitime::Epoch;
    use triblespace::macros::{find, pattern};

    use crate::egress::{
        self, answered, publish, request_fragment, requests, responses_for, with_view, Broker,
        Denial, RequestSpec, Status,
    };
    use crate::schemas::egress as egress_schema;
    use crate::storage::initialize_signer;

    /// A credential the broker holds and the requester must never see.
    const STUB_KEY: &str = "sk-stub-tavily-do-not-leak-6f9a2c";

    fn pinned_now() -> Result<IntervalValue> {
        crate::clock::point(Epoch::from_unix_seconds(1_700_000_000.0))
    }

    fn later() -> Result<IntervalValue> {
        crate::clock::point(Epoch::from_unix_seconds(1_700_000_060.0))
    }

    /// A backend that answers from a script instead of the network.
    struct StubBackend {
        /// Held only to prove it never reaches the requesting side.
        _api_key: String,
        fetched: std::cell::RefCell<Vec<String>>,
        outcome: std::result::Result<String, Refusal>,
    }

    impl StubBackend {
        fn returning(body: &str) -> Self {
            Self {
                _api_key: STUB_KEY.to_owned(),
                fetched: std::cell::RefCell::new(Vec::new()),
                outcome: Ok(body.to_owned()),
            }
        }

        fn failing(refusal: Refusal) -> Self {
            Self {
                _api_key: STUB_KEY.to_owned(),
                fetched: std::cell::RefCell::new(Vec::new()),
                outcome: Err(refusal),
            }
        }
    }

    impl Backend for StubBackend {
        fn serves(&self, _provider: Provider) -> bool {
            true
        }

        fn search(
            &self,
            _provider: Provider,
            query: &str,
            _max_results: usize,
        ) -> std::result::Result<Vec<SearchResult>, Refusal> {
            self.fetched.borrow_mut().push(query.to_owned());
            let body = self.outcome.clone()?;
            Ok(vec![SearchResult {
                url: "https://example.test/hit".to_owned(),
                title: Some(body),
                snippet: None,
            }])
        }

        fn fetch(
            &self,
            _provider: Provider,
            url: &str,
            _max_characters: usize,
        ) -> std::result::Result<String, Refusal> {
            self.fetched.borrow_mut().push(url.to_owned());
            self.outcome.clone()
        }
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        pile: PathBuf,
        key: PathBuf,
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("egress.pile");
        let key = directory.path().join("egress.key");
        File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        Fixture {
            _directory: directory,
            pile,
            key,
        }
    }

    impl Fixture {
        /// What `web request` does: no network, no vault, one commit.
        fn request(&self, operation: Id, target: &str, parameters: &[(&str, &str)]) -> Id {
            let spec = RequestSpec {
                faculty: DEFAULT_SCOPE_ID,
                operation,
                target: target.to_owned(),
                parameters: parameters
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                    .collect(),
                requester: None,
            };
            let (fragment, id) = request_fragment(&spec, pinned_now().unwrap()).unwrap();
            publish(
                &self.pile,
                Some(&self.key),
                egress_schema::DEFAULT_SCOPE_ID,
                fragment,
                "egress request",
            )
            .unwrap();
            id
        }

        fn sweep(&self, backend: StubBackend, policy: Policy) -> egress::Sweep {
            let mut broker = Broker::new(&self.pile, Some(&self.key));
            broker.register(Box::new(WebHandler::new(backend, policy).with_clock(later)));
            broker.sweep(later).unwrap()
        }

        fn responses(&self, request: Id) -> Vec<egress::ResponseRecord> {
            with_view(
                &self.pile,
                Some(&self.key),
                egress_schema::DEFAULT_SCOPE_ID,
                |facts, snapshot| responses_for(facts, snapshot, request),
            )
            .unwrap()
        }
    }

    #[test]
    fn a_request_serves_and_reads_back_without_a_socket() {
        let fixture = fixture();
        let request = fixture.request(
            OPERATION_FETCH,
            "https://example.test/page",
            &[("provider", "exa"), ("max-characters", "512")],
        );

        // Before the broker runs, nothing is answered.
        assert!(fixture.responses(request).is_empty());

        let sweep = fixture.sweep(StubBackend::returning("the page body"), Policy::default());
        assert_eq!(sweep.fulfilled, vec![request]);
        assert!(sweep.denied.is_empty());

        let responses = fixture.responses(request);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].status, Status::Fulfilled);
        let observation = responses[0]
            .observation
            .expect("fulfilment names its observation");

        // The observation is an ordinary Web fetch fact in the Web
        // collection: the same shape the direct path writes.
        with_view(
            &fixture.pile,
            Some(&fixture.key),
            DEFAULT_SCOPE_ID,
            |facts, snapshot| {
                let rows: Vec<(Id, String)> = find!(
                    (id: Id, provider: String),
                    pattern!(facts, [{
                        ?id @
                        metadata::tag: &web_schema::kind_fetch,
                        web_schema::provider: ?provider,
                    }])
                )
                .collect();
                assert_eq!(rows, vec![(observation, "exa".to_owned())]);

                let content: Vec<crate::egress::TextHandle> = find!(
                    value: crate::egress::TextHandle,
                    pattern!(facts, [{ observation @ web_schema::content: ?value }])
                )
                .collect();
                let view: anybytes::View<str> = snapshot.get(content[0]).unwrap();
                assert_eq!(&*view, "the page body");
                Ok(())
            },
        )
        .unwrap();
    }

    #[test]
    fn a_request_with_no_response_reads_as_pending_not_as_failure() {
        let fixture = fixture();
        let request = fixture.request(OPERATION_SEARCH, "canonical collections", &[]);

        with_view(
            &fixture.pile,
            Some(&fixture.key),
            egress_schema::DEFAULT_SCOPE_ID,
            |facts, snapshot| {
                // The request is there and readable...
                let found = requests(facts, snapshot, Some(DEFAULT_SCOPE_ID))?;
                assert_eq!(found.len(), 1);
                assert_eq!(found[0].id, request);
                assert_eq!(found[0].target, "canonical collections");
                // ...and simply has no answer yet, which is not an error.
                assert!(answered(facts).is_empty());
                assert!(responses_for(facts, snapshot, request)?.is_empty());
                Ok(())
            },
        )
        .unwrap();

        let broker = Broker::new(&fixture.pile, Some(&fixture.key));
        assert_eq!(
            broker
                .pending()
                .unwrap()
                .into_iter()
                .map(|record| record.id)
                .collect::<Vec<_>>(),
            vec![request]
        );
    }

    #[test]
    fn a_denied_request_is_readable_with_its_reason_and_is_never_reserved() {
        let fixture = fixture();
        let request = fixture.request(OPERATION_FETCH, "https://secret.test/page", &[]);

        let policy = Policy {
            allow_hosts: vec!["example.test".to_owned()],
            deny_hosts: Vec::new(),
        };
        let sweep = fixture.sweep(StubBackend::returning("never reached"), policy.clone());
        assert!(sweep.fulfilled.is_empty());
        assert_eq!(sweep.denied.len(), 1);

        let responses = fixture.responses(request);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].status, Status::Denied);
        assert_eq!(responses[0].denial, Some(Denial::Policy));
        assert!(responses[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("secret.test"));
        assert!(responses[0].observation.is_none());

        // A denial is terminal. A second sweep must not re-serve it, or the
        // refusal would be advisory rather than a decision.
        let again = fixture.sweep(StubBackend::returning("never reached"), policy);
        assert_eq!(again.handled(), 0);
        assert_eq!(fixture.responses(request).len(), 1);
    }

    #[test]
    fn a_provider_failure_is_recorded_with_its_category() {
        let fixture = fixture();
        let request = fixture.request(OPERATION_FETCH, "https://example.test/page", &[]);

        fixture.sweep(
            StubBackend::failing(Refusal::quota("provider replied 429")),
            Policy::default(),
        );

        let responses = fixture.responses(request);
        assert_eq!(responses[0].status, Status::Denied);
        assert_eq!(responses[0].denial, Some(Denial::Quota));
        assert!(responses[0].reason.as_deref().unwrap().contains("429"));
    }

    #[test]
    fn a_malformed_parameter_is_denied_rather_than_quietly_defaulted() {
        let fixture = fixture();
        let request = fixture.request(
            OPERATION_FETCH,
            "https://example.test/page",
            &[("max-characters", "as many as you like")],
        );

        let backend = StubBackend::returning("body");
        fixture.sweep(backend, Policy::default());

        let responses = fixture.responses(request);
        assert_eq!(responses[0].denial, Some(Denial::Malformed));
        assert!(responses[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("max-characters"));
    }

    #[test]
    fn a_request_this_broker_does_not_serve_is_denied_rather_than_left_pending() {
        let fixture = fixture();
        // A faculty with no handler registered: a `mail` request reaching a
        // web-only broker.
        let spec = RequestSpec {
            faculty: crate::schemas::mail::DEFAULT_SCOPE_ID,
            operation: OPERATION_FETCH,
            target: "someone@example.test".to_owned(),
            parameters: Vec::new(),
            requester: None,
        };
        let (fragment, request) = request_fragment(&spec, pinned_now().unwrap()).unwrap();
        publish(
            &fixture.pile,
            Some(&fixture.key),
            egress_schema::DEFAULT_SCOPE_ID,
            fragment,
            "egress request",
        )
        .unwrap();

        fixture.sweep(StubBackend::returning("body"), Policy::default());

        let responses = fixture.responses(request);
        assert_eq!(responses[0].denial, Some(Denial::Policy));
        assert!(responses[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("no handler"));
    }

    #[test]
    fn the_request_side_writes_no_secret_material_into_the_pile() {
        let fixture = fixture();
        // The requesting process holds no credential, so nothing it writes
        // can carry one. Scan the whole file it produced rather than trusting
        // a field list that a later change could grow.
        fixture.request(
            OPERATION_FETCH,
            "https://example.test/page",
            &[("provider", "tavily")],
        );

        let bytes = std::fs::read(&fixture.pile).unwrap();
        assert!(
            !bytes
                .windows(STUB_KEY.len())
                .any(|window| window == STUB_KEY.as_bytes()),
            "the requesting side wrote credential material into the pile"
        );
        // The target it *did* write is there, so the scan is meaningful.
        let target = b"https://example.test/page";
        assert!(bytes.windows(target.len()).any(|window| window == target));
    }

    #[test]
    fn a_request_is_found_by_querying_its_fields_not_by_rebuilding_its_id() {
        let fixture = fixture();
        let expected = fixture.request(OPERATION_SEARCH, "lattice-aware sync", &[]);

        // After construction an id is opaque. The sound way back to a request
        // is to match the facts it was built from.
        let found = with_view(
            &fixture.pile,
            Some(&fixture.key),
            egress_schema::DEFAULT_SCOPE_ID,
            |facts, snapshot| {
                let candidates: Vec<Id> = find!(
                    id: Id,
                    pattern!(facts, [{
                        ?id @
                        metadata::tag: &egress_schema::KIND_REQUEST,
                        request::faculty: &DEFAULT_SCOPE_ID,
                        request::operation: &OPERATION_SEARCH,
                    }])
                )
                .collect();
                let mut matching = Vec::new();
                for candidate in candidates {
                    let record = requests(facts, snapshot, None)?
                        .into_iter()
                        .find(|record| record.id == candidate);
                    if record.is_some_and(|record| record.target == "lattice-aware sync") {
                        matching.push(candidate);
                    }
                }
                Ok(matching)
            },
        )
        .unwrap();
        assert_eq!(found, vec![expected]);
    }
}
