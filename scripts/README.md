# Atomic local release cohorts

`install-release-cohort` installs every executable found directly in one build
directory as one content-verified, versioned generation. A generation path is
write-once by the installer: staging refuses to overwrite it, but the installer
does not claim filesystem immutability or remove owner write permission. Build
with `--workspace` so the
`migrations` binary — which lives in the `faculties-migrations` member crate and
owns the explicit collection-policy transition — is part of the cohort. The
installer refuses a build directory without it, so accidentally omitting
`--workspace` cannot activate an incomplete generation. It copies and hashes
the complete cohort
before atomically replacing `~/.local/lib/faculties/current`; commands in
`~/.local/bin` always pass through that symlink. The `mail` binary is exposed as
`faculties-mail` so the operating system's `mail(1)` is never shadowed.

Keep `~/.local/bin` before directories containing ad-hoc Faculties installs,
especially `~/.cargo/bin`. Activation checks the caller's `PATH` and refuses if
an earlier executable would shadow any command in the staged cohort; it never
deletes or rewrites that executable on the operator's behalf.

The installer refuses dirty Git repositories among the selected local Cargo
dependencies. Each generation carries `Cargo.lock` and a JSON manifest with
the exact source revisions and tree hashes, requested and resolved Cargo
features, verbose Cargo and rustc versions, the allowlisted `RUSTFLAGS` and
`CARGO_INCREMENTAL` environment when present, and SHA-256/size of every binary.
An exact GB10 runner can additionally provide its validated runner identity,
source-cohort digest, and argv receipt through `GB10_EXACT_INVOCATION`.
Untracked siblings and `target/` output outside that source closure do not block
a release.

Build and inspect without writing anything:

```sh
cargo build --release --workspace --bins --no-default-features
scripts/install-release-cohort target/release \
  --no-default-features --generation "$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short=12 HEAD)" \
  --dry-run
```

Stage the content-verified generation, validate its copied bytes, and only then
switch the complete command cohort:

```sh
scripts/install-release-cohort target/release \
  --no-default-features --generation <generation> --stage-only
scripts/install-release-cohort --activate-staged <generation> --dry-run
scripts/install-release-cohort --activate-staged <generation>
```

Omit `--stage-only` for a single stage-and-activate operation. Pass the same
`--features a,b` and `--no-default-features` choices used for `cargo build`;
they are recorded as provenance rather than guessed from opaque executables.
Existing commands not managed by this installer are never overwritten. Old
generations remain versioned under `~/.local/lib/faculties/releases/`, and the
installer never rewrites their paths; rollback is the same verified atomic
activation command with an older generation.

Activation changes the `current` symlink for **new** processes. A process that
was already running keeps its old executable mapped, even when its command path
now resolves through the new generation. Restart every long-lived Faculties
writer after an activation, especially each `orient wait` watcher. Check the
binary a process is actually executing rather than the current symlink:

```sh
lsof -a -d txt -p <pid>
```

This distinction is load-bearing for append-only piles: an apparently healthy
watcher from an older cohort can keep publishing records under superseded
semantics indefinitely.

Exercise the full install/switch path in an isolated temporary prefix:

```sh
python3 scripts/test_install_release_cohort.py
```
