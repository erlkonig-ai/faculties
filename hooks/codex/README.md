# Codex orient guard

These command-hook helpers keep the primary `liora-gpt` Codex window attached
to an `orient wait` process it can actually poll.

- `orient_session_start.sh` removes watchers inherited from inaccessible old
  exec sessions and injects watcher-first developer context.
- `orient_stop.sh` allows Stop only while a watcher is live. If it is absent,
  Codex gets one automatic continuation to poll, process, and rearm it; a second
  failed Stop remains visible but does not loop forever.

Wire them from the Liora project root's `.codex/hooks.json` as command handlers
for `SessionStart` (`startup|resume|clear|compact`) and `Stop`. Codex 0.144.1
ships stable hooks enabled by default. Project hooks are hash-trusted: review a
new or changed definition once with `/hooks` before expecting it to run.

The hook cannot itself start `orient wait`: command hooks are synchronous, and
a detached process would not be attached to the model's exec session. It
instead makes ownership and rearming a mechanically checked developer-context
obligation.
