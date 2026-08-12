= Relations: People and Handle Mappings

`relations` is the contact registry. Each entry maps a short
canonical label (the "handle") to a person record with names,
aliases, and free-form notes. Other faculties — most notably
`message` — resolve recipient handles through this
registry.

== Why a separate faculty

Each kind of state lives in its own fixed, signer-owned collection. Relations,
Message, and Compass therefore retain separate semantics while sharing one
pile. Faculties that need people-references materialize Relations without
claiming those facts as their own schema.

That separation matters when admitted facts merge. Two `relations add alice`
operations under the same durable signer mint distinct stable person anchors;
the read model preserves the ambiguity instead of silently choosing one by
label. Record an explicit same-person or distinct-person identity verdict when
you know the relationship, and reconcile concurrent profile frontiers
explicitly when needed. A concatenated foreign-signer COMMIT is retained
physically but is not admitted into this collection view. Message can therefore
reject an ambiguous addressee rather than inheriting inconsistent contact data.

== Usage

```sh
# Add a person
relations add operator --first-name "Ada" --last-name "Example" \
  --display-name "Ada" --affinity "user / project lead"

# Add an alias
relations add codex --display-name "Codex subagent" --alias "data-plane"

# List
relations list

# Show one (label, alias, or hex id all work)
relations show operator

# Update
relations set operator --note "Project lead. Prefers async over sync."
```

The label is the short form you'll type at faculty-call sites:
`message send operator "..."` resolves "operator" via the
relations registry.

== Conventions

  - Labels are lowercase, short, and easy to type. A profile update may rename
    one, but address by exact person id when durable identity matters and treat
    an old label as unavailable unless retained explicitly as an alias.
  - Display names are for UI rendering (GORBIE, log lines).
  - Aliases let you address the same person by multiple short forms
    (`ada`, `ada-example`, `operator`).
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
  - "Compass Goals Workflow" — `$PERSONA` attributes actions to a Relations
    person, while tags can request a person's or group's attention; neither is
    an exclusive assignment lock

Next stop: [Web: Search and Fetch Through Provider APIs](wiki:abe651f605c823085d861f296d9f9907).
