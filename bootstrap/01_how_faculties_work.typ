= How Faculties Work

Faculties are small CLI binaries — one per cognitive verb —
that all read and write the same
[TribleSpace pile](wiki:5232ea531fedfcb17bf15e88c3d52a36). The canonical upstream is
#link("https://github.com/triblespace/faculties")[github.com/triblespace/faculties];
install with `cargo install --git <repo> --bins`, or grab a
precompiled release tarball (every faculty plus the `trible`
CLI — no Rust toolchain needed; the tarball also carries
`bootstrap.pile`, the onboarding tour you are reading now).

== Mental model

  - One faculty = one cognitive verb:
    [`compass` for goals](wiki:7cdd48c272ff344628fe74f4c07783e4),
    [`wiki` for knowledge fragments](wiki:82129c70b693f7e2d781d78ac5efbb86),
    [`files` for archived artefacts](wiki:b08448855de9cce7610d68dac2555003),
    [`local_messages` for direct messages](wiki:65c6965cb3d11052e87804527734a697),
    and so on.
  - Each faculty owns a *branch* in the pile (`compass`,
    `wiki`, `files`, …) and writes its own signed commits
    there. Branches [merge independently](wiki:5cc10e2b0263008b261cf8a1ef30bd8c) —
    touching `compass` never invalidates `wiki`.
  - Every faculty honours `PILE=/path/to/self.pile` as an
    environment variable — set it once per session and skip
    `--pile` on every call. An explicit `--pile` (or, where
    supported, a positional path) always beats the env var.

== Discovery

`ls $(dirname $(which wiki))` shows every faculty next to the
one you found. Each binary explains itself with `--help`;
subcommands take their own `--help` for argument detail.
Invoking a faculty with no subcommand prints usage.

== Why this shape

The agent acts through shell commands and observes concrete
output. A faculty is the smallest possible "verb you can run
from a shell that produces a durable side effect." The pile is
the single source of truth — everything you think, decide, or
produce accretes there as content-addressed facts, which is
[what makes work its own ledger](wiki:996e648886cccb61d1afd48296b0a0cb). And because
the substrate underneath converges by construction, no faculty
contains [a single line of sync code](wiki:6e5f38bdfd589cd0359bf668d1af9841).

Next stop: [Substrate 1/4: What Is a Trible](wiki:4e19893b36bf37d471bb9ea968edac20).
