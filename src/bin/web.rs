//! `web` — search and browsing, on two paths that write the same facts.
//!
//! # Two paths, one ledger
//!
//! `search` and `fetch` are the **direct** path: they build an HTTP client,
//! resolve Tavily/Exa credentials out of the Secrets vault through Headspace,
//! perform the call in this process and commit the observation. That path is
//! unchanged and stays the right one for a window that has both a network
//! route and the keys.
//!
//! `request` and `result` are the **brokered** path, for a mind that has
//! neither. `request` writes what it wants into the Egress ledger and prints
//! the request id; a broker running outside the sandbox (`egress serve`)
//! performs it and writes back; `result` reads the answer. The pile is the
//! entire interface between the two sides.
//!
//! # Why this split exists
//!
//! **The keys never enter the sandbox — this is the larger half of the win.**
//! A resident mind's shell commands run in a VM with no internet, so the
//! direct path cannot work there at all. But the more important consequence is
//! the one that would still matter if the VM *did* have a network: before the
//! split, a model driving a shell was driving a process that held decrypted
//! provider credentials, so anything that reached that shell — prompt
//! injection through a fetched page, most obviously — reached the keys.
//! `web request` opens no socket and reads no vault. Only the broker, which
//! the mind cannot invoke and which runs under the supervision of whatever
//! enforces the sandbox, ever holds a credential.
//!
//! **Egress is auditable because every crossing is a durable fact.** Asking is
//! a fact, granting is a fact, refusing is a fact. "Everything this mind ever
//! asked the outside world for" and "what actually crossed, and when" are
//! queries over an append-only collection, not lines in a log that rotates.
//!
//! **Provenance travels with content.** A fulfilment names the observation it
//! produced; the observation carries the provider, the URL and the time. A
//! claim sourced from a fetched page traces back through the response to the
//! exact request that asked for it, and to whoever asked.
//!
//! **Denials are recorded, not dropped.** A request the broker refuses — bad
//! URL, host off the allow list, no credential for the named provider, the
//! provider erroring, a rate limit — comes back as a denial fact carrying its
//! category and its reason. A silently discarded request would be
//! indistinguishable from a slow one, and an unrecorded refusal would destroy
//! the auditability the design exists for. `result` reports pending, denied
//! and fulfilled as three different answers, and only an *unknown* request id
//! is an error.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::clock;
use faculties::egress::{self, Denial, RequestSpec, Status};
use faculties::schemas::egress as egress_schema;
use faculties::schemas::web::{web_schema, DEFAULT_SCOPE_ID};
use faculties::web::{
    self, ApiKeys, Backend, LiveBackend, Provider, SearchResult, PARAM_MAX_CHARACTERS,
    PARAM_MAX_RESULTS, PARAM_PROVIDER,
};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::BlobStoreGet;
use triblespace::macros::{find, pattern};
use triblespace::prelude::*;

type TextHandle = egress::TextHandle;

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "web", about = "Web search/browsing faculty (Tavily/Exa), directly or through a broker")]
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
    /// Do not write events to the pile; only print results. Direct path only.
    #[arg(long)]
    no_store: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Search the web for a query, in this process, using this process's keys.
    Search {
        #[arg(help = "Search query. Use @path for file input or @- for stdin.")]
        query: String,
        #[arg(long, default_value_t = web::DEFAULT_MAX_RESULTS)]
        max_results: usize,
        #[arg(long, value_enum, default_value_t = Provider::Auto)]
        provider: Provider,
    },
    /// Fetch and extract a URL, in this process, using this process's keys.
    Fetch {
        url: String,
        #[arg(long, value_enum, default_value_t = Provider::Auto)]
        provider: Provider,
        /// Max characters to return (provider permitting).
        #[arg(long, default_value_t = web::DEFAULT_MAX_CHARACTERS)]
        max_characters: usize,
    },
    /// Ask a broker for a crossing and print the request id.
    ///
    /// Needs no network route and no credential. This is the verb a sandboxed
    /// mind calls.
    Request {
        #[arg(help = "Search query or URL. Use @path for file input or @- for stdin.")]
        target: String,
        /// What to ask for.
        #[arg(long, default_value = "search", value_parser = ["search", "fetch"])]
        kind: String,
        /// Ask for a specific provider. Omitted means the broker chooses.
        #[arg(long, value_enum)]
        provider: Option<Provider>,
        /// Search only.
        #[arg(long)]
        max_results: Option<usize>,
        /// Fetch only.
        #[arg(long)]
        max_characters: Option<usize>,
        /// Anchor of whoever this is asked for, so a shared pile can still
        /// answer "everything *this* mind fetched, ever".
        #[arg(long)]
        requester: Option<String>,
    },
    /// Read the broker's answer to one request.
    ///
    /// Prints `status: pending`, `status: denied` or `status: fulfilled`. Only
    /// an unknown request id is an error — a request nobody has answered yet
    /// is pending, which is not a failure.
    Result {
        request: String,
        /// Keep re-reading until an answer appears or this long has passed.
        #[arg(long)]
        wait: Option<String>,
    },
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

    match cmd {
        Command::Search {
            query,
            max_results,
            provider,
        } => {
            let query = load_value_or_file(query, "search query")?;
            let backend = direct_backend(&cli, *provider)?;
            cmd_search(&cli, &backend, *provider, &query, *max_results)
        }
        Command::Fetch {
            url,
            provider,
            max_characters,
        } => {
            let backend = direct_backend(&cli, *provider)?;
            cmd_fetch(&cli, &backend, *provider, url, *max_characters)
        }
        Command::Request {
            target,
            kind,
            provider,
            max_results,
            max_characters,
            requester,
        } => {
            let target = load_value_or_file(target, "request target")?;
            cmd_request(
                &cli,
                &target,
                kind,
                *provider,
                *max_results,
                *max_characters,
                requester.as_deref(),
            )
        }
        Command::Result { request, wait } => cmd_result(&cli, request, wait.as_deref()),
    }
}

// --- The direct path: unchanged behaviour, now behind the Backend seam ---

fn direct_backend(cli: &Cli, requested: Provider) -> Result<LiveBackend> {
    LiveBackend::new(resolve_api_keys(cli, requested)?)
}

fn resolve_api_keys(cli: &Cli, requested_provider: Provider) -> Result<ApiKeys> {
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
        let configured = web::open_web_secrets(&cli.pile, cli.key.as_deref())?;
        tavily = tavily.or(configured.tavily);
        exa = exa.or(configured.exa);
    }
    Ok(ApiKeys { tavily, exa })
}

fn cmd_search(
    cli: &Cli,
    backend: &dyn Backend,
    provider: Provider,
    query: &str,
    max_results: usize,
) -> Result<()> {
    let provider = web::choose_provider(provider, backend).map_err(refusal_error)?;
    let results = backend
        .search(provider, query, max_results)
        .map_err(refusal_error)?;

    print_search_results(provider.name(), query, &results);

    if cli.no_store {
        return Ok(());
    }
    let (fragment, _) = web::search_fragment(provider, query, &results, clock::point_now()?)?;
    egress::publish(
        &cli.pile,
        cli.key.as_deref(),
        DEFAULT_SCOPE_ID,
        fragment,
        "web search observation",
    )
}

fn cmd_fetch(
    cli: &Cli,
    backend: &dyn Backend,
    provider: Provider,
    url: &str,
    max_characters: usize,
) -> Result<()> {
    let provider = web::choose_provider_fetch(provider, backend).map_err(refusal_error)?;
    let content = backend
        .fetch(provider, url, max_characters)
        .map_err(refusal_error)?;

    println!("{content}");

    if cli.no_store {
        return Ok(());
    }
    let (fragment, _) = web::fetch_fragment(provider, url, &content, clock::point_now()?)?;
    egress::publish(
        &cli.pile,
        cli.key.as_deref(),
        DEFAULT_SCOPE_ID,
        fragment,
        "web fetch observation",
    )
}

fn refusal_error(refusal: egress::Refusal) -> anyhow::Error {
    anyhow::anyhow!("{refusal}")
}

// --- The brokered path ---

fn cmd_request(
    cli: &Cli,
    target: &str,
    kind: &str,
    provider: Option<Provider>,
    max_results: Option<usize>,
    max_characters: Option<usize>,
    requester: Option<&str>,
) -> Result<()> {
    if target.trim().is_empty() {
        bail!("request target is empty");
    }
    let operation = web::operation(kind)?;

    // Only what was actually asked for is recorded. A default written here
    // would misreport the ask, and the broker's own default is the honest
    // place for it.
    let mut parameters = Vec::new();
    if let Some(provider) = provider {
        parameters.push((PARAM_PROVIDER.to_owned(), provider.name().to_owned()));
    }
    if let Some(max_results) = max_results {
        parameters.push((PARAM_MAX_RESULTS.to_owned(), max_results.to_string()));
    }
    if let Some(max_characters) = max_characters {
        parameters.push((PARAM_MAX_CHARACTERS.to_owned(), max_characters.to_string()));
    }

    let requester = requester
        .map(|raw| {
            Id::from_hex(raw.trim()).ok_or_else(|| anyhow::anyhow!("invalid requester id '{raw}'"))
        })
        .transpose()?;

    let spec = RequestSpec {
        faculty: DEFAULT_SCOPE_ID,
        operation,
        target: target.to_owned(),
        parameters,
        requester,
    };
    let (fragment, id) = egress::request_fragment(&spec, clock::point_now()?)?;
    egress::publish(
        &cli.pile,
        cli.key.as_deref(),
        egress_schema::DEFAULT_SCOPE_ID,
        fragment,
        "egress request",
    )?;

    println!("request: {id:X}");
    println!("faculty: web");
    println!("kind: {kind}");
    println!("target: {target}");
    println!("status: pending");
    println!();
    println!("read it back with: web result {id:X} --wait 2m");
    Ok(())
}

fn cmd_result(cli: &Cli, request: &str, wait: Option<&str>) -> Result<()> {
    let request = Id::from_hex(request.trim())
        .ok_or_else(|| anyhow::anyhow!("invalid request id '{request}'"))?;
    let deadline = wait
        .map(|raw| {
            humantime::parse_duration(raw).with_context(|| format!("parse --wait duration '{raw}'"))
        })
        .transpose()?
        .map(|duration| Instant::now() + duration);

    loop {
        let answer = read_answer(&cli.pile, cli.key.as_deref(), request)?;
        match answer {
            Answer::Unknown => bail!(
                "no Egress request {request:X} in this pile; \
                 `web request` prints the id it wrote"
            ),
            Answer::Pending(record) => {
                if deadline.is_some_and(|deadline| Instant::now() < deadline) {
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
                println!("request: {request:X}");
                println!("kind: {}", web::operation_name(record.operation));
                println!("target: {}", record.target);
                println!("status: pending");
                println!();
                println!("no broker has answered yet. This is not a failure.");
                return Ok(());
            }
            Answer::Answered(record, responses) => {
                let response = &responses[0];
                println!("request: {request:X}");
                println!("kind: {}", web::operation_name(record.operation));
                println!("target: {}", record.target);
                println!("status: {}", response.status.label());
                if responses.len() > 1 {
                    println!(
                        "note: {} responses recorded for this request; more than one \
                         broker served this collection",
                        responses.len()
                    );
                }
                match response.status {
                    Status::Denied => {
                        println!(
                            "denial: {}",
                            response.denial.map(Denial::label).unwrap_or("unrecorded")
                        );
                        println!(
                            "reason: {}",
                            response.reason.as_deref().unwrap_or("<none recorded>")
                        );
                        return Ok(());
                    }
                    Status::Fulfilled => {
                        let Some(observation) = response.observation else {
                            bail!("fulfilled response {:X} names no observation", response.id);
                        };
                        println!("observation: {observation:X}");
                        println!();
                        return print_observation(&cli.pile, cli.key.as_deref(), observation);
                    }
                }
            }
        }
    }
}

enum Answer {
    Unknown,
    Pending(egress::RequestRecord),
    Answered(egress::RequestRecord, Vec<egress::ResponseRecord>),
}

/// Find the request by matching its facts, then find responses that name it.
///
/// Neither step reconstructs an entity to recompute an id: after construction
/// an id is opaque, so the only sound way to reach a request is to query the
/// fields it was built from.
fn read_answer(pile: &Path, key: Option<&Path>, request: Id) -> Result<Answer> {
    egress::with_view(
        pile,
        key,
        egress_schema::DEFAULT_SCOPE_ID,
        |facts, snapshot| {
            let Some(record) = egress::requests(facts, snapshot, None)?
                .into_iter()
                .find(|record| record.id == request)
            else {
                return Ok(Answer::Unknown);
            };
            let responses = egress::responses_for(facts, snapshot, request)?;
            if responses.is_empty() {
                Ok(Answer::Pending(record))
            } else {
                Ok(Answer::Answered(record, responses))
            }
        },
    )
}

/// Render one Web observation exactly as the direct path would have printed
/// it, so a mind reading a brokered answer parses the same shape it would
/// have parsed from `web search` or `web fetch`.
fn print_observation(pile: &Path, key: Option<&Path>, observation: Id) -> Result<()> {
    egress::with_view(pile, key, DEFAULT_SCOPE_ID, |facts, snapshot| {
        let provider = find!(
            value: String,
            pattern!(facts, [{ observation @ web_schema::provider: ?value }])
        )
        .next()
        .unwrap_or_else(|| "unknown".to_owned());

        let is_fetch = find!(
            id: Id,
            pattern!(facts, [{
                ?id @ metadata::tag: &web_schema::kind_fetch
            }])
        )
        .any(|id| id == observation);

        if is_fetch {
            let Some(content) = find!(
                value: TextHandle,
                pattern!(facts, [{ observation @ web_schema::content: ?value }])
            )
            .next() else {
                bail!("fetch observation {observation:X} carries no content");
            };
            println!("{}", text(snapshot, content, "fetched content")?);
            return Ok(());
        }

        let query = match find!(
            value: TextHandle,
            pattern!(facts, [{ observation @ web_schema::query: ?value }])
        )
        .next()
        {
            Some(handle) => text(snapshot, handle, "search query")?,
            None => bail!("observation {observation:X} is neither a fetch nor a search"),
        };

        let mut results = Vec::new();
        for hit in find!(
            hit: Id,
            pattern!(facts, [{ observation @ web_schema::result: ?hit }])
        ) {
            let Some(url) = find!(
                value: TextHandle,
                pattern!(facts, [{ hit @ web_schema::url: ?value }])
            )
            .next() else {
                continue;
            };
            let title = find!(
                value: TextHandle,
                pattern!(facts, [{ hit @ web_schema::title: ?value }])
            )
            .next();
            let snippet = find!(
                value: TextHandle,
                pattern!(facts, [{ hit @ web_schema::snippet: ?value }])
            )
            .next();
            results.push(SearchResult {
                url: text(snapshot, url, "result url")?,
                title: title
                    .map(|handle| text(snapshot, handle, "result title"))
                    .transpose()?,
                snippet: snippet
                    .map(|handle| text(snapshot, handle, "result snippet"))
                    .transpose()?,
            });
        }
        print_search_results(&provider, &query, &results);
        Ok(())
    })
}

fn text(snapshot: &PileSnapshot, handle: TextHandle, label: &str) -> Result<String> {
    let view: anybytes::View<str> = snapshot
        .get(handle)
        .with_context(|| format!("read Web {label}"))?;
    Ok(view.to_string())
}

fn print_search_results(provider: &str, query: &str, results: &[SearchResult]) {
    println!("provider: {provider}");
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
    fn the_brokered_verbs_are_present_and_take_no_credential() {
        let command = Cli::command();
        let request = command
            .get_subcommands()
            .find(|sub| sub.get_name() == "request")
            .expect("web exposes a request verb");
        let arguments = request
            .get_arguments()
            .map(|argument| argument.get_id().as_str().to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(!arguments.contains("tavily_api_key"));
        assert!(!arguments.contains("exa_api_key"));
        assert!(command
            .get_subcommands()
            .any(|sub| sub.get_name() == "result"));
    }

    #[test]
    fn explicit_provider_override_does_not_require_headspace_or_a_pile() {
        let missing = PathBuf::from("/definitely/not/a/web-test.pile");
        let cli = Cli {
            pile: missing,
            key: None,
            tavily_api_key: Some(" explicit-tavily-key ".to_owned()),
            exa_api_key: None,
            no_store: true,
            command: None,
        };
        let keys = resolve_api_keys(&cli, Provider::Tavily).unwrap();
        assert_eq!(keys.tavily.as_deref(), Some("explicit-tavily-key"));
        assert!(keys.exa.is_none());
    }
}
