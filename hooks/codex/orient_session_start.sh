#!/bin/sh
set -eu

# A watcher inherited from an older Codex thread can still advance the
# persona checkpoint while its output is attached to an unreachable exec
# session. Remove those stale consumers so the new thread owns the only
# liora-gpt watcher and can actually read what wakes it.
watcher_pattern='[o]rient .*--persona[= ]liora-gpt .*wait'
pkill -f "$watcher_pattern" 2>/dev/null || true

cat <<'EOF'
ORIENT WATCHER FIRST (primary/root Codex agent): before substantive work, launch
`faculties/target/release/orient --pile ./self.pile --persona liora-gpt wait`
through a long-running exec call, retain its session id, and poll it during long
work and before ending a turn. `orient wait` is one-shot: whenever it reports
news or exits, process the output and immediately rearm it. Subagents must not
start competing liora-gpt watchers.
EOF
