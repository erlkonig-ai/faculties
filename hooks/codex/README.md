# Codex Orient wake bridge

These command-hook helpers keep the primary Codex window attached to a
one-shot `orient_wait.sh` wrapper it can poll. Orient detects news; the wrapper
queues that news into the same Codex conversation, starting another turn even
when the previous turn has ended. Set `ORIENT_PERSONA` (or the shared
`PERSONA`) to the relations label or id this window owns. They default to the
host project's `self.pile`; set `ORIENT_PILE` to an absolute path when the pile
lives elsewhere.

They resolve `orient` through the atomically activated local release at
`~/.local/lib/faculties/current/bin/orient` (or
`$FACULTIES_RELEASE_ROOT/current/bin/orient`). This prevents a hook from opening
a pile with a stale checkout build while the interactive commands use a newer
cohort.

Launch from a primary/root Codex long-running exec session, not as a detached
shell job or from a subagent:

```sh
sh faculties/hooks/codex/orient_wait.sh "$CODEX_THREAD_ID" \
  --pile "$PILE" --persona "$PERSONA"
```

The first argument is the exact destination thread id; the remaining arguments
are Orient options, and the wrapper appends `wait`. It inherits the invoking
Codex installation, `CODEX_HOME`, account and local app-server connection. It
does not resume a second owner, override permissions/model settings, or move a
conversation to another host. Remote-server routing is not configured by this
wrapper.

- Capture one successful, nonempty Orient report on stdout. `DRIVE_ENDPOINT`
  is unset only for that child so a Drive transport cannot consume the report.
- Print the report into the exec log, then pass it as one quoted `--message`
  argument to `codex queue --thread ID`. The envelope labels it as forwarded
  tool output, not new user-authored instructions. No output is evaluated.
- Retry queue failures every five seconds with the **same** captured report;
  do not call Orient again after it has recorded those events as Presented.
- Exit after queue acceptance. The awakened root processes relevant news and
  rearms the wrapper. This is one notification, not a perpetual "continue" loop.

The report is retained in the running wrapper and its exec output, not in a
new durable spool. Killing that process can interrupt delivery; ambiguous queue
failures can also produce duplicates. Queue acceptance is not proof that the
model has processed the event. Existing event identities and acknowledgements
remain authoritative; do not treat forwarding as completing the work.

- `orient_session_start.sh` removes only a matching watcher that is provably
  orphaned (a direct child of init), then injects watcher status or
  watcher-first developer context. A live watcher is preserved even when this
  hook cannot tell which Codex window owns its exec session; hand ownership off
  explicitly instead of killing it speculatively.
- `orient_prompt_submit.sh` injects directed Orient news on every prompt using
  `orient poll --peek`. Codex fires prompt hooks for root and subagents without
  identifying which fired, so peek deliberately records no `Presented` facts
  for the configured persona.
- `orient_stop.sh` allows Stop only while a watcher is live. If it is absent,
  Codex gets one automatic continuation to poll, process, and rearm it; a second
  failed Stop remains visible but does not loop forever.

Both lifecycle hooks match the configured persona and canonical pile rather
than an order-sensitive command substring. They accept either flag order,
`--flag=value` and `--flag value`, relative pile paths resolved from the
watcher's cwd, the faculty's `PILE` / `PERSONA` environment fallbacks, and any
executable path whose basename is exactly `orient` (including release symlinks
and checkout-relative launches). The wrapper, including `sh orient_wait.sh`,
also counts as live **during queue retries after Orient exits**. A wrapper and
its child are one watcher owner, not two competing subscriptions.
Because `ps` does not preserve argument boundaries, paths and persona labels
containing whitespace are intentionally not inferred from process listings.

Wire them from the host project root's `.codex/hooks.json` as command handlers
for `SessionStart` (`startup|resume|clear|compact`), `UserPromptSubmit`, and
`Stop`. Codex 0.144.1 ships stable hooks enabled by default. Project hooks are
hash-trusted: review a new or changed definition once with `/hooks` before
expecting it to run.

The SessionStart hook deliberately does not launch a detached watcher. It
passes the exact `session_id` from the hook envelope (falling back to the Codex
thread environment) in a launch instruction for the primary agent. Ownership,
polling and rearming stay in that agent's long-running exec session. The Stop
hook supplies the same command if rearming was missed.

Tests (no real model, account or pile calls):

```sh
sh faculties/hooks/codex/orient_process_test.sh
sh faculties/hooks/codex/orient_wait_test.sh
```
