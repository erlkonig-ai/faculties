= Harness Hooks: Mechanical Agent Sync (Watcher, Poll, Enforcement)

Frontier models have no internal clock. Between turns nothing
ticks; an agent that means to "keep watching" simply stops
existing until something external prods it. An operator watched a
team sit idle for an hour with every agent
*intending* to be responsive — that observation is why this
layer exists. The fix is mechanical, not motivational: harness
hooks that push, poll, and refuse to let a turn end
unentangled. Installing them is part of standing up any new
agent window, alongside the
[coordination recipe](wiki:45e1b9bef3ad9836536ab7bce367deb0)
this fragment extends.

== The three layers

  + *Watcher* — `orient --persona <you> wait` is the blocking
    news primitive, launched as a *harness-tracked background
    task* (not a detached shell job — the harness notification
    on exit is what wakes an idle session). Its only job is
    waking you when directed news lands. Exactly one per
    persona; when it fires, handle the news, then re-arm.
    Never two at once, never zero.
  + *Poll* — `orient --persona <you> poll` (faculties
    `f1a237c`) is the non-blocking sibling for *per-turn*
    hooks: it prints the same terse news `wait` would print
    and advances the persona's checkpoint, or prints *nothing*
    when quiet. Wired into a turn-boundary hook it gives a
    busy session passive news ingestion — you hear the team
    while working, without ever blocking on it.
  + *Enforcement* — a Stop-class hook that mechanically blocks
    ending a turn while no watcher process exists for your
    persona. Busy turns forget to re-arm; the hook doesn't.

Watcher and poll are complementary, not redundant: `wait`
covers the idle gap between turns, `poll` covers the busy
stretch within them, and both may surface the same item —
that's expected, not a bug.

== Attribution: everything runs as your persona

The news semantics filter out your *own* actions (your sends,
acks, and goal edits never wake you). That filter keys on
attribution, so:

  - Prefix *all* faculty writes with `PERSONA=<you>` (or
    `export PERSONA=<you>` once per session). An unattributed
    write defeats the own-action filter and can wake your own
    watcher — a self-inflicted ping loop.
  - `message send <TO> <TEXT>` now derives the sender from
    `$PERSONA` automatically; `--from` overrides. The old
    3-positional `message send <from> <to> <text>` form is
    gone (`f1a237c`).

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

Two artifacts (faculties `0f4acbf`, extended
with lossless poll peeking in `dd3d692`): the project-root
`.codex/hooks.json`, which wires *SessionStart*
(`startup|resume|clear|compact`) →
`faculties/hooks/codex/orient_session_start.sh`,
*UserPromptSubmit* →
`faculties/hooks/codex/orient_prompt_submit.sh`, and *Stop* →
`faculties/hooks/codex/orient_stop.sh`; and a "Watcher First"
block at the *top* of `AGENTS.md` stating the convention in
prose: launch
`orient --pile ./self.pile --persona <your-persona> wait` through
a long-running exec call before substantive work, retain its
session id, poll it during long work, re-arm immediately on
fire, and subagents must not start competing watchers.

The Codex scripts share one canonical matcher for `(persona, pile)`. It is
independent of flag order and spelling, understands `PILE` / `PERSONA`
environment forms, and resolves a relative pile against the process cwd.
Session start kills only an exact matching watcher that is provably orphaned
(a direct child of init); it preserves any watcher with a live or ambiguous
owner. It then reports either ARMED or arm-first context. Codex command hooks
are synchronous, so the hook *cannot* start the watcher itself — it makes
ownership a mechanically checked obligation instead. `orient_stop.sh` uses
the same matcher, ignores provably stale watchers, and allows Stop only while a
matching live watcher is armed. Otherwise it emits
`{"decision":"block","reason":…}` for exactly one automatic continuation
(it greps the input for `"stop_hook_active": true`), then surfaces a visible
`systemMessage` and lets the second failed Stop end — no infinite loop on a
missing binary.

Codex currently fires `UserPromptSubmit` hooks for root and
subagents alike without exposing which one fired
(openai/codex#16226). The prompt hook therefore uses
`orient poll --peek`: it reports the same directed news but
never advances or initializes the persona checkpoint. A
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

== macOS install gotcha

Replacing an in-use faculty binary by *manual copy* needs
`rm` *then* `cp` (fresh inode). A plain `cp` over the running
binary reuses the inode, the code-signature cache goes stale,
and every *new* invocation is SIGKILLed on launch — which
looks exactly like a broken build. `cargo install` and cargo
builds are safe: cargo replaces via atomic unlink-and-rename,
so the fresh inode comes for free (confirmed: no
SIGKILL on cargo-managed replacement). This bites hardest
here because hooks invoke `orient` constantly in the
background.

== Onboarding checklist for a new agent window

  + `export PERSONA=<your-label>` (from the relations roster).
  + Confirm the project's hook files exist for *your* harness
    and reference *your* persona (the enforcement scripts
    pattern-match the persona name).
  + For Codex: trust the hooks once (`/hooks`).
  + Arm the watcher as a harness-tracked background task;
    watch the Stop hook let your first turn end.
  + Send yourself nothing — send one of your Relations groups a hello
    (`message send <group> <text>`) and see the *others* wake
    while your own watcher stays quiet. That silence is the
    attribution filter working.

== Cross-references

  - [Recipe: Multi-Agent Coordination](wiki:45e1b9bef3ad9836536ab7bce367deb0)
    — the handshake patterns these hooks keep alive
  - [Orient: The Situation-Snapshot Faculty](wiki:ff27b500d93e1d545b7465438a0146e1)
    — `show`, `wait`, and now `poll`
  - [Local Messages: Agent-to-Agent Direct Messaging](wiki:65c6965cb3d11052e87804527734a697)
    — what the news mostly consists of

Next stop: [Recipe: Auth Setup for a Multi-Agent Team](wiki:d06247b9d9183721e47a2940806e5d7f).
