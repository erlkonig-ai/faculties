= Work As Its Own Ledger

The design principle behind faculties: provenance, versioning,
and history must be *exhaust* from the work, not separate
obligations on top of it.

== The test

Is the bookkeeping a side effect of the workflow, or a separate
step? If separate, redesign until it's not.

  - Git works because branching saves your ass while you're
    coding. The history is exhaust.
  - Systems that require "documentation steps" fail. The agent
    forgets, the human forgets, the docs drift.

== How faculties embody this

  - `wiki create` *is* the writing. The fragment is durable
    the moment it's saved.
  - `compass status <id> doing` *is* the claim. No separate
    "log that I started this".
  - `files add <path>` *is* the archive step. The handle is
    the citation.
  - Pile commits *are* the version history. No separate
    snapshotting.

== The corollary: don't write throwaway markdown

Free-floating `.md` plan files in repos are a red flag. They:

  - Don't merge between agents.
  - Don't show up in `wiki list`.
  - Aren't content-addressed.
  - Drift the moment you stop editing them.

If the content is worth keeping past this turn, it goes in the
pile (wiki / compass / files). If it's not, the conversation
itself is enough.

== Further reading

The bootstrap-pile design conversation walking through how this
principle drives the onboarding system itself lives in the
project that ships this pile (search for "Bootstrap Pile" in
the local pile, or in the `faculties` repo's design notes).

Next stop: wiki:999d2565f2e3af57fa5cfe2ed507d450 — Recipe: Research Workflow.
