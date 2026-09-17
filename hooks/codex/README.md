# Persistent Orient delivery to Codex

One `orient daemon` keeps the pile open, observes changes, and delivers each
complete report to a callback on stdin. `orient_queue.sh` is only the
delivery adapter: it calls `codex queue` once for the exact owning thread.
It does not wait, rearm, poll, retry, print the report, or run a model.

Before enabling the daemon, remove the old Orient SessionStart,
UserPromptSubmit and Stop entries from the host's hook configuration and
stop its owned one-shot wrapper. Remove watcher-first/rearm instructions from
the host's agent instructions too. Do not run prompt-time `poll --peek` or
log forwarding alongside the daemon: they are competing delivery paths.
Codex's `/hooks` interface can inspect and disable individual non-managed
hooks ([official hook documentation](https://learn.chatgpt.com/docs/hooks#review-and-trust-hooks)).
Changing these source files does not change an existing host configuration.

After explicitly selecting the owning thread, pile and persona, launch the
installed release in one supervised process or retained long-running exec:

```sh
"${FACULTIES_RELEASE_ROOT:-$HOME/.local/lib/faculties}/current/bin/orient" \
  --pile "$PILE" --persona "$PERSONA" daemon \
  --callback /bin/sh \
  --callback-arg "$PWD/faculties/hooks/codex/orient_queue.sh" \
  --callback-arg "$CODEX_THREAD_ID"
```

Use absolute callback paths in a service. The callback inherits the owning
Codex installation's PATH, CODEX_HOME, account and local connection; never
guess a destination thread or launch a second conversation owner. Confirm the
installed Codex supports `codex queue --thread ID --message TEXT`.

Callback success records existing Presented receipts. It means queue
acceptance, not that the agent read or completed the work. The callback
preserves UTF-8 text including trailing newlines; text is one literal argv
value, never shell code. Shell argv limits still apply to large reports.
Callback stdout is discarded and diagnostics use stderr. No report appears
in both the daemon's tool output and the conversation queue.

Delivery failure or the default 30-second callback timeout exits the daemon
without recording that report as presented. There is no internal retry.
Inspect the failure before restarting its sole owner; do not rebuild a
sleep/rearm loop beside it. A crash between queue acceptance and recording
the receipt can still cause a duplicate: this is best effort, not exactly-once
delivery. Habit completion remains a separate source operation.

`--callback-timeout 10s` changes the per-delivery bound;
`--run-for 1m` bounds a test observation; `--poll-ms 1000` controls the
pile growth check. These options do not add another notification path.
Ordinary manual `wake`, `show`, `poll` and one-shot `wait` remain available.

Run the isolated mock transport test without live services:

```sh
sh faculties/hooks/codex/orient_queue_test.sh
```
