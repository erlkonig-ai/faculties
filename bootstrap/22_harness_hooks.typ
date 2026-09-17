= Harness Hooks: Mechanical Agent Sync

Orient noticing news and the harness delivering it into a conversation are
different operations. A background process finishing is not necessarily a
model-turn wakeup. Use one persistent `orient daemon` with one delivery
callback, rather than a collection of watcher, polling and rearm hooks.
This is the notification setup for the
[coordination recipe](wiki:45e1b9bef3ad9836536ab7bce367deb0).

== One open pile, one delivery path

The daemon keeps its pile open while observing changes and time-driven Habits.
Each complete report goes to the configured executable on stdin. The executable
is invoked directly with literal argv, without shell interpretation of news.
Its stdout is discarded; stderr is diagnostic output, not another notification.
Exit zero accepts the handoff and lets Orient record existing Presented
receipts. That means seen, not handled: completing a Habit or acknowledging a
Message remains the corresponding source faculty's operation.

A callback failure or timeout exits the daemon without recording that report
as seen. There is no durable delivery spool or internal retry loop. A crash
after delivery but before the receipt can still cause a duplicate; this is
best effort, not exactly-once delivery. Inspect an error before restarting,
and keep exactly one owner per persona/pile pair.

== Codex

Before enabling a daemon, disable and remove old Orient SessionStart,
UserPromptSubmit and Stop hook entries in the host configuration. Also remove
watcher-first and rearm instructions from its AGENTS.md. Do not keep prompt-time
`orient poll --peek`, log forwarding or a shell rearm loop beside the daemon.
Those are competing presentation paths, not extra reliability.
The [official hooks interface](https://learn.chatgpt.com/docs/hooks#review-and-trust-hooks)
can inspect and disable non-managed hooks. Source edits alone do not update a
host's installed configuration.

Use the installed release and launch one supervised process or retained
long-running exec on the conversation's host:

```sh
"${FACULTIES_RELEASE_ROOT:-$HOME/.local/lib/faculties}/current/bin/orient" \
  --pile "$PILE" --persona "$PERSONA" daemon \
  --callback /bin/sh \
  --callback-arg "$PWD/faculties/hooks/codex/orient_queue.sh" \
  --callback-arg "$CODEX_THREAD_ID"
```

`orient_queue.sh` reads stdin, preserves the complete report including trailing
newlines, and invokes `codex queue --thread ID --message TEXT` once. It does not
print news, poll Orient, sleep or retry. Check `codex queue --help` on the
installation that owns the conversation. Shell argument-size limits apply.

Keep the two identities explicit:

  - `PERSONA` / `--persona` selects the Relations identity whose attention
    is observed. It is not a destination conversation.
  - `CODEX_THREAD_ID` identifies the exact existing Codex thread receiving
    news. Never guess it, paste a different window's id, or start a second
    conversation owner to manufacture delivery.

The callback inherits the owner's PATH, CODEX_HOME, account and connection.
Use absolute paths in a service. Subagents must not launch competing observers.
No rearm is needed when a callback succeeds: the same daemon continues.
`--callback-timeout 30s` bounds each callback; `--run-for 1m` bounds a test run.

== Other harnesses and obsolete hook recipes

Claude Code and Antigravity previously used per-turn poll hooks and Stop
enforcement around one-shot waits. Those recipes are historical, not setup
instructions for the daemon. Their host-specific configurations are not
changed by installing new Faculty source or binaries.

A different harness needs its own small delivery callback with the same stdin
and exit-status contract. Disable its old notification hooks and log forwarders
before installing that single path. Do not assume the Codex callback works for
another harness, and do not adapt a delay/rearm workaround as the daemon's
supervisor.

== Attribution and Habit routing

Directed-message and Compass news filter out the observer's own actions.
Set `PERSONA` explicitly for faculty writes so sender attribution is retained.
`message send <TO> <TEXT>` uses that persona by default; `--from` overrides it.
Forwarded news retains its original sender and authority rather than becoming
a new instruction from the operator.

Habit definitions may carry explicit persona targets. Orient selects global
habits plus those targeting its persona before evaluating their conditions.
`habit add --persona <label-or-exact-id>` is repeatable; omission is global,
not an implicit use of PERSONA. This is routing, not a security boundary.
Seeing a due occurrence does not complete it.

== Installed cohorts and onboarding

Use `faculties/scripts/install-release-cohort` for the tested native binary
cohort. Do not overwrite a running binary or use `cargo install --path faculties
--bins`, which can leave a stale shadow installation. Activation only affects
new processes: hand the single daemon owner over explicitly after updates.

For a new agent window:

  + Select its persona, pile, signing key and exact conversation thread.
  + Disable the old notification/rearm/poll paths, preserving unrelated hooks.
  + Launch one daemon with the callback and inspect its stderr for failures.
  + Have another agent send one ordinary message after the turn has ended.
    Verify one new turn receives it and the same daemon remains alive.
  + Reply normally, without requesting another test reply or constructing an
    acknowledgement loop. A live process or queue success alone is not the
    full end-to-end delivery test.

== Cross-references

  - [Recipe: Multi-Agent Coordination](wiki:45e1b9bef3ad9836536ab7bce367deb0)
  - [Orient: The Situation-Snapshot Faculty](wiki:ff27b500d93e1d545b7465438a0146e1)
  - [Local Messages: Agent-to-Agent Direct Messaging](wiki:65c6965cb3d11052e87804527734a697)

Next stop: [Recipe: Share a Collection Between Agents](wiki:d06247b9d9183721e47a2940806e5d7f).
