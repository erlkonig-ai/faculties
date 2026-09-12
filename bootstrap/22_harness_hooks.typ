= Harness Hooks: Mechanical Agent Sync (Watcher, Poll, Enforcement)

Between turns, the harness decides whether another model turn starts.
An intention to "keep watching" is not a callback. There are two distinct
events: Orient notices news, then the harness delivers it into a conversation.
A background process completing does not by itself guarantee the second.
Hooks and an appropriate delivery bridge connect them. Installing this
connection is part of standing up any new
agent window, alongside the
[coordination recipe](wiki:45e1b9bef3ad9836536ab7bce367deb0)
this fragment extends.

== The three layers

  + *Watcher* — `orient --persona <you> wait` is the blocking
    news primitive, launched as a *harness-tracked background
    task*, with the harness-specific delivery mechanism below. A bare
    wait can notify a Claude Code monitor; Codex uses a one-shot wrapper
    that queues the report into the owning conversation. Keep exactly one
    owner for each `(persona, pile)` pair. When it finishes, process the
    news and re-arm; do not start a competing wait during delivery retries.
  + *Poll* — `orient --persona <you> poll` (faculties
    `f1a237c`) is the non-blocking sibling for *per-turn*
    hooks: it prints the same terse news `wait` would print
    and records exactly the reported events as `Presented`, or prints *nothing*
    when quiet. Wired into a turn-boundary hook it gives a
    busy session passive news ingestion — you hear the team
    while working, without ever blocking on it.
  + *Enforcement* — a Stop-class hook that mechanically blocks
    ending a turn while no watcher process exists for your
    persona. Busy turns forget to re-arm; the hook doesn't.

Watcher and poll are complementary, not redundant: `wait` plus its delivery
bridge covers the idle gap between turns, `poll` covers the busy
stretch within them, and both may surface the same item —
that's expected, not a bug.

== Attribution: everything runs as your persona

Directed-message and Compass news filter out your *own* actions (your sends,
acks, and attributed goal edits stay quiet). That filter keys on
attribution, so:

  - Prefix *all* faculty writes with `PERSONA=<you>` (or
    `export PERSONA=<you>` once per session). An unattributed
    write defeats the own-action filter and can wake your own
    watcher — a self-inflicted ping loop.
  - `message send <TO> <TEXT>` now derives the sender from
    `$PERSONA` automatically; `--from` overrides. The old
    3-positional `message send <from> <to> <text>` form is
    gone (`f1a237c`).

Persona selection is not an isolation boundary for every event kind. In the
current implementation, Habit evaluation is not filtered by persona: an
intention meant for another agent can still wake your watcher. Honor its
ownership instead of completing it on that agent's behalf. Fix recipient
selection in the Habit/Orient model, not by interpreting notification text
as a new instruction from the operator.

== Claude Code

Hooks live in the *project-scope* `.claude/settings.json`
(committed, so every session in the repo inherits them), with
scripts in `.claude/hooks/`. Four scripts across three events:

  - *SessionStart* (`startup|resume|clear|compact`):
    `inject-memory.sh` (nudges the waking agent to self-fetch
    a memory cover) then `inject-watcher-status.sh`.
  - *UserPromptSubmit*: `poll-news.sh`.
  - *Stop*: `check-watcher.sh`.

`inject-watcher-status.sh` first *cleans up orphaned
watchers*: a watcher whose spawning session died gets
re-parented to PID 1, so `ps -o ppid= -p $pid` returning `1`
is the staleness test — live sessions' watchers keep a live
shell parent. Stale ones are killed *by exact PID only*,
never by pkill-pattern (other personas share the process
name). It then injects `additionalContext` reporting ARMED
("do not arm a second one") or NOT ARMED ("arm it NOW,
before other work").

`poll-news.sh` runs `orient --persona $PERSONA poll`; if the
output is empty it exits silently, otherwise it wraps the news
as JSON `additionalContext`:

```sh
jq -n --arg n "$NEWS" '{"hookSpecificOutput":
  {"hookEventName":"UserPromptSubmit",
   "additionalContext":("=== ORIENT NEWS (orient poll) ===\n" + $n + "…")}}'
```

`check-watcher.sh` is the enforcement layer. If no
`orient --persona $PERSONA wait` process exists it emits
`{"decision": "block", "reason": "WATCHER NOT ARMED …"}` with
the exact re-arm command in the reason. Two guards keep it
from looping forever: when the input JSON has
`stop_hook_active: true` (i.e. we're already in a
hook-forced continuation) it downgrades to feedback-only
`additionalContext`, and the platform's 8-block cap
force-exits pathological cases. Fail-open throughout: no
`orient` binary or no pile means never block.

== Codex

The project-root
`.codex/hooks.json`, which wires *SessionStart*
(`startup|resume|clear|compact`) →
`faculties/hooks/codex/orient_session_start.sh`,
*UserPromptSubmit* →
`faculties/hooks/codex/orient_prompt_submit.sh`, and *Stop* →
`faculties/hooks/codex/orient_stop.sh`, supplies the lifecycle guards.
The one-shot delivery bridge is `faculties/hooks/codex/orient_wait.sh`
(introduced in Faculties `f3833407`, tested with Codex CLI `0.153.4`).
Check `codex queue --help` on the installation that owns the conversation.
A bare long-running exec completing is not the Codex idle-wake mechanism.

Keep the two identities separate:

  - `PERSONA` / `--persona` selects the Relations identity whose attention
    Orient observes. Set it to *this window's* identity; do not copy another
    window's persona into shared hook definitions.
  - The hook envelope's `session_id` selects the Codex conversation receiving
    the report. The hooks pass that exact id, with `CODEX_THREAD_ID` /
    `CODEX_SESSION_ID` as environment fallbacks. Never guess it or paste a
    different window's id. The
    [official hook contract](https://learn.chatgpt.com/docs/hooks#common-input-fields)
    also specifies that subagent hooks carry their parent's session id;
    subagents therefore must not start their own competing watcher.

Put a "Watcher First" block at the top of the host workspace's `AGENTS.md`:
the primary agent launches the following from its own Codex environment
through a long-running exec before substantive work, retains the returned
exec session id, and polls it during work and before ending a turn.

```sh
sh faculties/hooks/codex/orient_wait.sh "$CODEX_THREAD_ID" \
  --pile "$PILE" --persona "$PERSONA"
```

Use the exact thread id supplied by the hook if the environment variable is
absent. The wrapper appends `wait`; do not append it yourself. It resolves the
installed `current/bin/orient`, captures one successful nonempty report,
prints it into the exec log, and passes it literally to
`codex queue --thread ID --message TEXT`. It unsets `DRIVE_ENDPOINT` only for
the Orient child so the report reaches stdout. No second conversation owner,
model override, or permanent model-driving loop is created.

Launch on the conversation's host with its own `CODEX_HOME` / account and
app-server environment. The wrapper does not configure remote routing. When
handing over an existing bare watcher, poll and drain its owned exec session
first; never kill another live window's watcher to make room.

On queue failure, the wrapper retains and retries the *same* report instead
of consuming more Orient events. Keep that exec session while it retries.
On successful delivery it exits, and the root processes the news and rearms.
The report may already have been read from the exec session when its queued
copy arrives; use the original event ids and acknowledgements to avoid doing
the work twice. Queue acceptance is not a message read receipt. Retention is
in the running wrapper and exec output, not a crash-durable spool, so this is
not an exactly-once or process-crash delivery guarantee.

The Codex scripts share one canonical matcher for `(persona, pile)`. It is
independent of flag order and spelling, understands `PILE` / `PERSONA`
environment forms, and resolves a relative pile against the process cwd.
Session start kills only an exact matching watcher that is provably orphaned
(a direct child of init); it preserves any watcher with a live or ambiguous
owner. It then reports either ARMED or arm-first context. The hook deliberately
leaves launching to the primary agent's tracked exec, rather than detaching
a process whose output the agent cannot poll. `orient_stop.sh` uses
the same matcher, ignores provably stale watchers, and allows Stop only while a
matching live watcher is armed. Otherwise it emits
`{"decision":"block","reason":…}` for exactly one automatic continuation
(it greps the input for `"stop_hook_active": true`), then surfaces a visible
`systemMessage` and lets the second failed Stop end — no infinite loop on a
missing binary. The wrapper itself counts as live while delivery retries,
even after its Orient child exits; those two processes are one watcher owner.

Codex currently fires `UserPromptSubmit` hooks for root and
subagents alike without exposing which one fired
(openai/codex#16226). The prompt hook therefore uses
`orient poll --peek`: it reports the same directed news but
never adds `Presented` facts. A
worker may see repeated news, but cannot steal it from the
root watcher. The hook exits silently when quiet and wraps
news as `hookSpecificOutput.additionalContext` when present.

*Trust caveat*: Codex treats project hooks as untrusted on
first sight (hash-trusted). The operator must "Trust all and continue"
at the prompt, or review once via `/hooks`, before a new or
*changed* hook definition runs. Silent hook inaction after an
edit usually means the hash changed and re-trusting is due.

== Antigravity

Landed 2026-07-12 (mechanism verified the same
day) — this documents the artifacts on disk; check them if
they have iterated since. `.agents/hooks.json` defines one
enabled hook group, `blood-law-watcher`, wiring *Stop* →
`./.agents/hooks/check_watcher.sh` and *PreInvocation* →
`./.agents/hooks/pre_invocation.sh`.

Antigravity's Stop schema *inverts* Claude Code's vocabulary:
the hook outputs `{"decision": "continue", "reason": "…"}` on
stdout to *block* turn-end (i.e. "continue working"), and
`{"decision": "stop"}` to allow it. The landed
`check_watcher.sh` checks `ps -ef` for
`orient --persona <your-persona> wait` and emits the
continue-decision ("Blood Law violated: No watcher armed!")
when missing. `pre_invocation.sh` is the poll layer: it runs
`orient --persona <your-persona> poll` and outputs

```json
{"injectSteps": [{"ephemeralMessage": "…NEW ORIENT MESSAGES:…"}]}
```

— news injected as an ephemeral message when there is any, a
standing watcher reminder when quiet. That quiet path is a
deliberate divergence from Claude Code's poll hook: Antigravity's
variant applies *constant pressure* (a reminder every turn,
never silent), Claude Code's is *signal-only* (silent when
quiet). Both are valid; pick per harness temperament. As
landed it paths `faculties/target/debug/orient`; expect that
to move to the installed/release binary.

== Installed binary cohorts

Use `faculties/scripts/install-release-cohort` for a tested, complete native
binary cohort; hooks resolve the atomically activated `current/bin/orient`.
Do not overwrite running binaries or use `cargo install --path faculties
--bins`: a second install can shadow the cohort and silently become stale.
On macOS, overwriting a mapped executable's inode can also invalidate the
code-signature cache. Activation affects new processes; hand existing watchers
over explicitly after a cohort update. Changing only these shell hooks needs
no Rust build.

== Onboarding checklist for a new agent window

  + `export PERSONA=<your-label>` (from the relations roster).
  + Confirm the project's hook files exist for *your* harness
    and reference *your* persona (the enforcement scripts
    pattern-match the persona name).
  + For Codex: verify `codex queue --help`, trust new/changed hook definitions
    through `/hooks`, and keep the persona and destination thread distinct.
  + Arm the appropriate watcher/bridge as a harness-tracked background task;
    watch the Stop hook let your first turn end.
  + Have another agent send one ordinary message *after your turn has ended*.
    Verify that a new turn receives it, acknowledge that exact message, and
    rearm. A live process or a successful queue call alone is not the full test.
  + Send a reply without asking for another test reply. Your own attributed
    send should stay quiet; avoid building a loop of agents acknowledging
    each other's acknowledgements.

== Cross-references

  - [Recipe: Multi-Agent Coordination](wiki:45e1b9bef3ad9836536ab7bce367deb0)
    — the handshake patterns these hooks keep alive
  - [Orient: The Situation-Snapshot Faculty](wiki:ff27b500d93e1d545b7465438a0146e1)
    — `show`, `wait`, and now `poll`
  - [Local Messages: Agent-to-Agent Direct Messaging](wiki:65c6965cb3d11052e87804527734a697)
    — what the news mostly consists of

Next stop: [Recipe: Share a Collection Between Agents](wiki:d06247b9d9183721e47a2940806e5d7f).
