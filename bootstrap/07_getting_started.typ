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

  - [How Faculties Work](wiki:25e8f009e33207755109f19f7a68dff5) — the faculty model and shell-first
    causality
  - [Wiki Fragment Style Guide](wiki:82129c70b693f7e2d781d78ac5efbb86) — typst, atomic, cross-linked
  - [Compass Goals Workflow](wiki:7cdd48c272ff344628fe74f4c07783e4) — todo / doing / blocked / done
  - [Work As Its Own Ledger](wiki:996e648886cccb61d1afd48296b0a0cb) — the principle behind faculties
  - [Tool Selection: Faculties First](wiki:f4aff48fff04f313552f5b32244f9873) — quick-lookup table for
    "which tool here?"
  - "Getting Started: Your First Hour" (this fragment)

*Specific faculties* — read when you reach for one:

  - [Files Faculty: Archiving and Citing Artefacts](wiki:b08448855de9cce7610d68dac2555003)
  - [Teams: Capability-Based Membership](wiki:67477d2173928fd91ef20173eabfeae4)
  - [Local Messages: Agent-to-Agent Direct Messaging](wiki:65c6965cb3d11052e87804527734a697)
  - [Orient: The Situation-Snapshot Faculty](wiki:ff27b500d93e1d545b7465438a0146e1)
  - [Relations: People and Handle Mappings](wiki:e7e3f672a66b39e0b5b3c0eaf212b1da)
  - [Web: Search and Fetch Through Provider APIs](wiki:abe651f605c823085d861f296d9f9907)

*Recipes* — chained-faculty workflows for common tasks:

  - [Recipe: Research Workflow](wiki:999d2565f2e3af57fa5cfe2ed507d450) — compass → web → files
    → wiki, end-to-end for "investigate something and write
    it up"
  - [Recipe: Multi-Agent Coordination](wiki:45e1b9bef3ad9836536ab7bce367deb0) — relations +
    local_messages + orient + compass for two-agent handoffs
    without race conditions or silent drops
  - [Harness Hooks: Mechanical Colony Sync](wiki:5c86df3dcd5994de2967483fca7170ac) — watcher +
    poll + turn-end enforcement per harness (Claude Code,
    Codex, Antigravity); models have no internal clock, so
    coordination is hook-enforced, not remembered
  - [Recipe: Auth Setup for a Multi-Agent Team](wiki:d06247b9d9183721e47a2940806e5d7f) — `trible
    team` + `pile net` for bootstrapping capability auth
    across two machines so the relay accepts both peers

*Substrate concepts* — the in-depth "why does this work"
layer. Not needed for day-one productivity; read when you
want to understand what's underneath the faculties:

  - [Substrate 1/4: What Is a Trible](wiki:4e19893b36bf37d471bb9ea968edac20) — 64-byte
    content-addressable facts
  - [Substrate 2/4: The Pile](wiki:5232ea531fedfcb17bf15e88c3d52a36) — one append-only file,
    nothing ever deleted
  - [Substrate 3/4: Monotonic Merge](wiki:5cc10e2b0263008b261cf8a1ef30bd8c) — why N peers sync
    without conflicts, by construction
  - [Substrate 4/4: The Architecture — Zero Sync Code](wiki:6e5f38bdfd589cd0359bf668d1af9841)
    — agents, faculties, workspace, substrate: why no faculty
    contains sync code

Read the foundations in any order; each stands alone. Tool
Selection is the densest if you want a single-page reference.
For "where was I?" at session start, run `orient show`
before reading anything.

Next stop: [How Faculties Work](wiki:25e8f009e33207755109f19f7a68dff5).
