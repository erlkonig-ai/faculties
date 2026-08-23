= Web: Search and Fetch Through Provider APIs

`web` is the agent's web access faculty. Backed by Tavily or
Exa (provider configured via API key). Two operations: `search`
to query the web, `fetch` to pull and clean a single URL.

== Why this exists

  - Direct `curl` from the agent loses provenance — the bytes
    arrive but no record of where they came from. `web`
    persists each request as a pile event with the URL, query,
    timestamp, and response.
  - Provider APIs (Tavily / Exa) extract clean
    text/markdown from cluttered HTML, which beats raw scraping
    for downstream processing.
  - The Web collection becomes a queryable history: "have I
    already pulled this URL? what did it say?" answered without
    re-fetching.

== Usage

```sh
# Search using the exact credential version selected through Headspace.
web search "succinct hash array mapped trie"

# Or override one invocation explicitly (use @path or @- to avoid shell history).
web --tavily-api-key @/secure/path/tavily.key search \
  "succinct hash array mapped trie"

# Fetch a URL (clean markdown when the provider supports it)
web fetch https://arxiv.org/abs/2305.12345
```

`fetch` returns clean text. If you want the original bytes
(PDFs, datasets), use `files fetch <url>` instead — that
archives the raw response under a content hash.

== Coordination with files

A common pattern:

  + `web search "<query>"` — find candidate URLs.
  + Pick a result.
  + `files fetch <url>` — archive the raw bytes
    (`files:<hash>` returned).
  + `wiki create "..." --tag paper` — write a fragment
    citing the `files:<hash>`.

So web is the discovery / clean-extract step; files is
the durable-archive step. Use the right one for each job.

== When NOT to use it

  - Pages that need authentication or interactive
    JavaScript — provider APIs handle static content well, but
    SPA-heavy pages may return shells.
  - Bulk crawling — the provider cost adds up; `wget`/`curl` +
    files is cheaper at volume.
  - Bulk history inspection. The current `web` CLI is an action surface and has
    no list/history subcommand; build a domain query before relying on stored
    events for duplicate avoidance.

== Collection and storage

Unless `--no-store` is set, each `search` and `fetch` publishes an immutable
event into one fixed, team-rooted Web collection. There is no branch selector
or mutable head. Events accrete; nothing is overwritten. Runtime credentials
come from exact Secrets versions selected through Headspace, or from explicit
per-invocation overrides; they are not stored in the public event facts.

Next stop: [Tool Selection: Faculties First](wiki:f4aff48fff04f313552f5b32244f9873).
