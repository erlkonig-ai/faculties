# AGENT Instructions

If you're an AI agent working in this repo, this is your reference. The
human-facing project description and install steps are in
[`README.md`](README.md); this file is the part you actually live with.

## What faculties are

Small, single-file CLIs that persist their state in a TribleSpace pile.
Each binary lives at `src/bin/<name>.rs`, owns a named branch on the
pile (e.g. `wiki`, `compass`, `message`), and is designed to
coexist with the others on the same pile. Shared schemas + GORBIE
widgets live in `src/lib.rs` (and `src/widgets/` under the `widgets`
feature).

## Editing a faculty

* Each `src/bin/<name>.rs` is meant to stand alone — read it
  end-to-end before changing it. The single-file property is
  deliberate; resist the urge to extract helpers into `src/lib.rs`
  unless the duplication is causing actual drift bugs across three
  or more faculties.
* Schemas (attribute IDs, shared kinds) live under
  [`src/schemas/`](src/schemas/) and are imported via
  `use faculties::schemas::<faculty>::*;`. New attribute IDs go
  there, never hand-rolled inside a binary.
* When you need a new stable ID — schema, attribute, kind — mint it
  with `trible genid` and paste the exact output. Never guess hex,
  even temporarily. Record the minted value in the commit message.
* Each binary's deps are unioned into the root `Cargo.toml`. Add
  per-faculty deps there; comment them with the faculty that needs
  them so the next agent can grep for "what does X need".

## Running locally

```sh
# from the repo root
cargo build --bin wiki --release
./target/release/wiki list --tag bootstrap

# or once-off without building first
cargo run --bin compass --release -- list

# install everything onto $PATH
cargo install --path . --bins
```

`PILE` is read from the environment by every faculty (clap's native
env-var support). Set it once per shell — `export PILE=./self.pile`
— and skip the `--pile` flag.

## Bootstrap pile

`bootstrap.pile` ships curated onboarding fragments + compass goals
for fresh agents. Sources are `bootstrap/*.typ`; rebuild with
`bootstrap/build.sh` (which `cargo build --release`s the wiki +
compass bins on demand). The build script's sanity-check phase
asserts the expected fragment + goal counts — if you add or remove
entries, bump the `EXPECTED_FRAGMENTS` / `EXPECTED_GOALS` constants
to match.

## CI / releases

* `.github/workflows/release.yml` fires on `v*` tags. It builds
  every CLI faculty for x86_64-linux-gnu, aarch64-linux-gnu (via
  cross), x86_64-apple-darwin, and aarch64-apple-darwin, then
  attaches a tarball + sha256 per target to the GH release.
* The `widgets` feature is enabled by default, so `viewer` and the
  capture binaries are included in normal builds and release
  tarballs. Use `--no-default-features` for a CLI-only build.
* Bumping the version: edit `version` in `Cargo.toml`, move the
  unreleased CHANGELOG entries under a new `## X.Y.Z — YYYY-MM-DD`
  heading, `cargo check` to refresh the lockfile, commit, then
  tag `vX.Y.Z` — the workflow does the rest.

## Conventions

* **Single-file faculty.** A new faculty is a new `src/bin/<name>.rs`
  + a new module in `src/schemas/<name>.rs`. No helper crates, no
  framework abstraction, nothing clever.
* **Faithful CLI to pile.** Every faculty operation is one
  triblespace commit on its branch. The CLI is a thin shell over
  the data model — surface arguments map directly to attributes.
* **No shadow datamodels.** If state belongs in the pile, query the
  pile on demand via `pattern!` / `find!`. Don't pre-materialise
  into structs/maps.
* **`PILE` env var, not flags.** Faculties default to `PILE` from
  the environment; `--pile` is the override, not the primary path.
* **Atomic commits.** Each faculty operation produces one commit
  with a descriptive message. The pile's commit log is the audit
  trail.

## Push / PR

Direct commit to `main` is the convention here (and across the
triblespace-org repos). PRs are reserved for cross-org coordination
that doesn't apply within this project. "Direct" describes the Git
transport, not an absence of review: a main-bound candidate gets an exact
Compass request and independent attestations from a frozen review council
before it is pushed. The roster must include the author and at least one
distinct peer. Every frozen member must respond; the author may abstain, while
every non-author must approve.
`compass review gate <request>` is the scriptable check;
`compass review settle <request>` records the proof and
closes its goal. Proof events are content-derived and guarded transitions
re-evaluate on branch conflicts; sealed attestations must remain the unique
active heads after replicas merge, so an offline-concurrent vote fails closed.
Never use raw `compass move` once structured review history exists. After a
commit or rebase changes the candidate, explicitly
open a successor request for the new exact target; that invalidates the old
approvals and re-notifies the peer reviewers through Orient. Tag releases with
`vX.Y.Z`; the GH workflow handles the rest.

## License

Dual MIT / Apache-2.0. Don't change without asking.
