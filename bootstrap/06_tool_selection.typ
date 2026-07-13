= Tool Selection: Faculties First

A quick lookup for "which tool do I reach for here?"

== Goals and tasks

  - *Use* `compass add` / `move` / `note`.
  - *Don't use* the harness's TaskCreate / TaskUpdate for
    persistent goals — those vanish at end of session.
  - *Do use* TaskCreate inline within a single conversation when
    you need a step-tracker for "the next 20 minutes". Compass
    is for "still on my plate next week".

== Knowledge fragments

  - *Use* `wiki create / edit / lint`.
  - *Don't use* free-floating `.md` files in repos.
  - *Exception*: when a downstream consumer needs the file at a
    specific path (a crate's `CHANGELOG.md`, a `book/src/`
    chapter rendered by mdbook), then `.md` is correct.

== Files (PDFs, datasets, binaries)

  - *Use* `files add <path>`. Returns a `files:<hash>` handle
    you cite from wiki fragments.
  - *Don't use* `/tmp` for anything you'll want past this turn.
  - *Don't commit* binaries to repos — they bloat the history.

== Direct messages between agents

  - *Use* `message` for in-place agent-to-agent
    messaging (append-only, with read acknowledgements).
  - For shared knowledge between two agents: a wiki fragment
    they both query is usually better than a message.

== Subagents

  - *Use* codex for parallelisable / token-heavy work where
    supervision overhead is amortised (see the "When to Use
    Codex" bootstrap fragment).
  - *Use* the harness's Agent tool for short focused
    sub-tasks that share your conversational context (e.g.
    "Explore: find files matching pattern X").
  - *Don't use* either for tasks under ~5 min — direct execution
    beats subagent-launch overhead.

== Plans

  - *Prefer* in-conversation plans + compass goals.
  - *Don't* write `PLAN.md` / `TODO.md` files in repos. They
    accrete stale sections.
  - *Exception*: an explicit user request for a written plan
    document, where the user wants to review before execution.

Next stop: [Work As Its Own Ledger](wiki:996e648886cccb61d1afd48296b0a0cb).
