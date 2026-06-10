= Relations: People and Handle Mappings

`relations` is the contact registry. Each entry maps a short
canonical label (the "handle") to a person record with names,
aliases, and free-form notes. Other faculties — most notably
`local_messages` — resolve recipient handles through this
registry.

== Why a separate faculty

The pile branch model means each kind of state lives on its own
branch. Relations stay on `relations`; messages on
`local-messages`; goals on `compass`. Faculties that need
people-references read from `relations` without owning the data.

That separation matters when piles merge: two agents independently
adding a person record for "alice" produce content-addressed
duplicates the lint pass can deduplicate; if relations were
inlined into local-messages each merge would risk inconsistent
addressee data.

== Usage

```sh
# Add a person
relations add jp --first-name "Jan-Paul" --last-name "Bultmann" \
  --display-name "JP" --affinity "user / project lead"

# Add an alias
relations add codex --display-name "Codex subagent" --alias "data-plane"

# List
relations list

# Show one (label, alias, or hex id all work)
relations show jp

# Update
relations set jp --note "Project lead. Prefers async over sync."
```

The label is the short form you'll type at faculty-call sites:
`local_messages send jp "..."` resolves "jp" via the
relations registry.

== Conventions

  - Labels are lowercase, short, alphanumeric. Stable across
    sessions — once chosen, don't rename.
  - Display names are for UI rendering (GORBIE, log lines).
  - Aliases let you address the same entity by multiple
    short forms (`jp`, `bulti`, `liora-jp`).
  - Notes are free-form; affinity is the one-liner ("user",
    "team member", "external collaborator").

== When NOT to use it

  - For ad-hoc "who is this?" lookups during a single session
    — that's the conversation context, not durable state.
  - For network identities (iroh node ids, cap-sig handles) —
    those live in the team CLI's pile state, not in relations.
    Relations is about *people*, not network nodes.

== Cross-references

  - "Local Messages: Agent-to-Agent Direct Messaging" — the
    primary consumer of the relations registry
  - "Compass Goals Workflow" — goals can be assigned to a
    relations label (some compass workflows use this for
    multi-agent kanban)

Next stop: wiki:abe651f605c823085d861f296d9f9907 — Web: Search and Fetch Through Provider APIs.
