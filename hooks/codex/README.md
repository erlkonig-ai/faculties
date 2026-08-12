# Codex orient guard

These command-hook helpers keep the primary Codex window attached to an
`orient wait` process it can actually poll. Set `ORIENT_PERSONA` (or the shared
`PERSONA`) to the relations label or id this window owns. They default to the
host project's `self.pile`; set `ORIENT_PILE` to an absolute path when the pile
lives elsewhere.

They resolve `orient` through the atomically activated local release at
`~/.local/lib/faculties/current/bin/orient` (or
`$FACULTIES_RELEASE_ROOT/current/bin/orient`). This prevents a hook from opening
a pile with a stale checkout build while the interactive commands use a newer
cohort.

- `orient_session_start.sh` removes only a matching watcher that is provably
  orphaned (a direct child of init), then injects watcher status or
  watcher-first developer context. A live watcher is preserved even when this
  hook cannot tell which Codex window owns its exec session; hand ownership off
  explicitly instead of killing it speculatively.
- `orient_prompt_submit.sh` injects directed Orient news on every prompt using
  `orient poll --peek`. Codex fires prompt hooks for root and subagents without
  identifying which fired, so peek deliberately never advances or initializes
  the configured persona checkpoint.
- `orient_stop.sh` allows Stop only while a watcher is live. If it is absent,
  Codex gets one automatic continuation to poll, process, and rearm it; a second
  failed Stop remains visible but does not loop forever.

Both lifecycle hooks match the configured persona and canonical pile rather
than an order-sensitive command substring. They accept either flag order,
`--flag=value` and `--flag value`, relative pile paths resolved from the
watcher's cwd, the faculty's `PILE` / `PERSONA` environment fallbacks, and any
executable path whose basename is exactly `orient` (including release symlinks
and checkout-relative launches).
Because `ps` does not preserve argument boundaries, paths and persona labels
containing whitespace are intentionally not inferred from process listings.

Wire them from the host project root's `.codex/hooks.json` as command handlers
for `SessionStart` (`startup|resume|clear|compact`), `UserPromptSubmit`, and
`Stop`. Codex 0.144.1 ships stable hooks enabled by default. Project hooks are
hash-trusted: review a new or changed definition once with `/hooks` before
expecting it to run.

The SessionStart hook cannot itself start `orient wait`: command hooks are
synchronous, and a detached process would not be attached to the model's exec
session. It instead makes ownership and rearming a mechanically checked
developer-context obligation.
