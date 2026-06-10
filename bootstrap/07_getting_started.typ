= Getting Started: Your First Hour

Welcome. You're an AI agent landing in this workspace for the
first time. This fragment walks you through orienting yourself
and starting to do work.

== Step 1: orient your environment (10 min)

  + `ls $(dirname $(which wiki))` — see what faculties exist
    on your PATH (or `ls path/to/faculties/` if you haven't put
    them on PATH yet).
  + `wiki list --tag bootstrap` — see all the onboarding
    fragments (this one + the foundation + per-faculty fragments).
  + `compass list` — see active goals.
  + `compass list todo` (filter to a tag with `--tag bootstrap`
    if there are non-onboarding goals mixed in) — see your
    bootstrap tasks.

== Step 2: project-specific context

If you're inheriting an existing project (vs. starting fresh),
look for a `wiki --pile ./self.pile show <id>` "letter from
the previous instance" or similar onboarding handoff in the
local pile — projects like Liora seed one as the first thing
to read. `wiki search "letter"` or `wiki list --tag
onboarding` from your local pile should surface it.

If there isn't one, skip this step.

== Step 3: do the bootstrap goals (30 min)

The compass has a handful of `#bootstrap`-tagged goals walking
you through hands-on faculty use:

  - mint an id with `trible genid`
  - create your first wiki fragment
  - link two fragments
  - archive a file
  - run `wiki lint` and `wiki check`
  - add a compass note to one of your goals

Working through these gives you the muscle memory the docs
can't.

== Step 4: pick up real work (15 min)

  + `compass list doing` — anything in flight you should
    take over?
  + If nothing's in flight, ask the user (look up their handle
    via `relations list` if you don't already know it) what
    they need next.

== If you get stuck

  - `wiki search <keyword>` — full-text across all
    fragments.
  - Re-run any faculty with `--help`.
  - Check `CLAUDE.md` (project root) for project-specific
    conventions that override defaults.
  - Ask the user.

== Sibling fragments

`wiki list --tag bootstrap` enumerates the onboarding
fragments by id and title. The set covers two shapes:

*Foundations* — read first if you've never used faculties:

  - "How Faculties Work" — the faculty model and shell-first
    causality
  - "Wiki Fragment Style Guide" — typst, atomic, cross-linked
  - "Compass Goals Workflow" — todo / doing / blocked / done
  - "When to Use Codex (and When Not To)" — control-plane vs
    data-plane
  - "Work As Its Own Ledger" — the principle behind faculties
  - "Tool Selection: Faculties First" — quick-lookup table for
    "which tool here?"
  - "Getting Started: Your First Hour" (this fragment)

*Specific faculties* — read when you reach for one:

  - "Files Faculty: Archiving and Citing Artefacts"
  - "Teams: Capability-Based Membership"
  - "Local Messages: Agent-to-Agent Direct Messaging"
  - "Orient: The Situation-Snapshot Faculty"
  - "Relations: People and Handle Mappings"
  - "Web: Search and Fetch Through Provider APIs"

*Recipes* — chained-faculty workflows for common tasks:

  - "Recipe: Research Workflow" — compass → web → files
    → wiki, end-to-end for "investigate something and write
    it up"
  - "Recipe: Multi-Agent Coordination" — relations +
    local_messages + orient + compass for two-agent handoffs
    without race conditions or silent drops
  - "Recipe: Auth Setup for a Multi-Agent Team" — `trible
    team` + `pile net` for bootstrapping capability auth
    across two machines so the relay accepts both peers

*Substrate concepts* — the in-depth "why does this work"
layer. Not needed for day-one productivity; read when you
want to understand what's underneath the faculties:

  - "Substrate 1/3: What Is a Trible" — 64-byte
    content-addressable facts
  - "Substrate 2/3: The Pile" — one append-only file,
    nothing ever deleted
  - "Substrate 3/3: Monotonic Merge" — why N peers sync
    without conflicts, by construction

Read the foundations in any order; each stands alone. Tool
Selection is the densest if you want a single-page reference.
For "where was I?" at session start, run `orient show`
before reading anything.
