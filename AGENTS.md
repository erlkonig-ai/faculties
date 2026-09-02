# AGENT Instructions

If you're an AI agent working in this repo, this is your reference. The
human-facing project description and install steps are in
[`README.md`](README.md); this file is the part you actually live with.

## What faculties are

Small CLIs that persist their state in a TribleSpace pile. Each binary lives at
`src/bin/<name>.rs` and publishes through one or more fixed, descriptor-policy
collections. A collection is identified by its semantic descriptor; its value
is the monotonic union of COMMIT fragments signed by keys with exact positive
WRITE authority, not a mutable named branch. Shared domain models, schemas,
validation, cutover logic, and GORBIE
widgets live in `src/lib.rs` (and `src/widgets/` under the `widgets`
feature).

## Editing a faculty

* Keep binaries as thin orchestration shells. Reusable domain construction,
  validation, and read models belong in `src/lib.rs`; UI projections belong in
  `src/widgets/`. Read both the binary and its library module before changing
  either boundary.
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

# build and atomically install the complete workspace cohort onto $PATH
cargo build --release --workspace --bins --locked
scripts/install-release-cohort target/release
```

The installer stages a content-verified, versioned generation and refuses to
rewrite an existing generation path. That is a write-once installer policy,
not filesystem immutability: generation files remain owner-writable, and the
installer does not `chmod` them read-only.

Atomic activation affects only processes launched afterward. Restart all
long-lived Faculties writers after installing a cohort, especially armed
`orient wait` watchers; use `lsof -a -d txt -p <pid>` to verify the executable
generation actually mapped by a surviving process.

The `migrations` binary lives in the `faculties-migrations` member crate, so
whole-suite builds need `--workspace` (`cargo build --release --workspace
--bins`). Without it the cohort silently ships without the explicit
collection-policy transition.

`PILE` is read from the environment by every faculty (clap's native
env-var support). Set it once per shell — `export PILE=./self.pile`
— and skip the `--pile` flag.

## Portable bootstrap

The `bootstrap` binary imports curated onboarding entries + Compass goals
as locally signed collection COMMITs. Sources are `bootstrap/*.typ`; their
declarative manifest and fixed occurrence times live in `src/bootstrap.rs`;
Compass goal and note ids are derived by their normal constructors. Import only
after explicitly initializing the destination's durable signer
(`trible pile signing-key init <pile>`). Never
copy a pre-signed seed pile: a destination's explicit WRITE authority does not
implicitly authorize its builder key. Run `bootstrap/build.sh` for the
fresh-recipient, exact-replay, and semantic-closure checks.

For each of the 21 seeded Wiki entries, a later bootstrap generation advances
only the recognizable imported source strand. Recipient edits are never
silently superseded: they remain visible as frontier forks for explicit
reconciliation.

## CI / releases

* `.github/workflows/release.yml` fires on `v*` tags. It builds
  every CLI faculty for x86_64-linux-gnu, native aarch64-linux-gnu,
  and aarch64-apple-darwin, then
  attaches a tarball + sha256 per target to the GH release.
* Faculties, TribleSpace, Mary, and the CubeCL fork are a pinned sibling source
  cohort. The release workflow checks out the exact revisions named there;
  local source installs must use the same layout documented in `README.md`.
* The `widgets` feature is enabled by default, so `viewer` and the
  capture binaries are included in normal builds and release
  tarballs. Use `--no-default-features` for a CLI-only build.
* Bumping the version: edit `version` in `Cargo.toml`, move the
  unreleased CHANGELOG entries under a new `## X.Y.Z — YYYY-MM-DD`
  heading, `cargo check` to refresh the lockfile, commit, then
  tag `vX.Y.Z` — the workflow does the rest.

## Conventions

* **Thin faculty binary.** A new faculty normally has
  `src/bin/<name>.rs`, a reusable domain module, and a schema module. Share
  capabilities when several faculties need the same model; keep the CLI a
  small projection over that library.
* **Faithful CLI to pile.** Each publication into one collection commits one
  self-contained `Fragment`; a compound operation may publish to several fixed
  collections. Construct all dependent fragments before the first
  `Collection::commit`, and make an interrupted operation safely replayable.
  Strictly validate untrusted reads and migration inputs; do not rescan the
  entire current union before ordinary writes unless the domain has a real
  cross-fragment compatibility invariant. Never introduce a mutable head,
  branch selector, or CAS loop.
* **No shadow datamodels.** If state belongs in the pile, query the
  pile on demand via `pattern!` / `find!`. Don't pre-materialise
  into structs/maps.
* **`PILE` env var, not flags.** Faculties default to `PILE` from
  the environment; `--pile` is the override, not the primary path.
* **Atomic COMMITs.** Each individual collection publication produces one
  independent signed COMMIT. Facts are the collection element, metafacts are
  its canonical metadata, and referenced attachments travel with the
  Fragment. Exact retries must be idempotent.

## Push / PR

Direct commit to `main` is the convention here (and across the
triblespace-org repos). PRs are reserved for cross-org coordination
that doesn't apply within this project. Reviews, when requested, are
asynchronous diagnostics against an exact artifact: reviewers record what
they observed, where, and with what evidence. They do not prescribe a fix,
own Compass status, or block the author from continuing. A finding may become
a normal follow-up goal after it is checked against the current artifact;
later development may already have removed its cause. Any release or
publication policy belongs at that boundary, not inside Compass. Tag releases
with `vX.Y.Z`; the GH workflow handles the rest.

## License

Dual MIT / Apache-2.0. Don't change without asking.
