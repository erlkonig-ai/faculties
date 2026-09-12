#!/bin/sh
set -eu

# Read the event envelope. SessionStart currently gives us no trustworthy
# root/subagent ownership bit, so process cleanup below must remain conservative.
input=$(cat)

persona=${ORIENT_PERSONA:-${PERSONA:-}}
if [ -z "$persona" ]; then
    echo 'Orient hook disabled: set ORIENT_PERSONA or PERSONA to the relations persona this window owns.'
    exit 0
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/orient_process.sh"
faculties_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
project_dir=$(CDPATH= cd -- "$faculties_dir/.." && pwd)
wrapper="$script_dir/orient_wait.sh"
thread=$(printf '%s' "$input" | orient_hook_thread_id)
pile=${ORIENT_PILE:-"$project_dir/self.pile"}
case "$pile" in
    /*) ;;
    *) echo 'Orient hook disabled: ORIENT_PILE must be an absolute path.'; exit 0 ;;
esac

# A direct init child has lost the harness exec session that owned its output.
# Kill only that exact stale PID. A watcher whose ownership cannot be proven
# stale may belong to this window (or another live one) and is never killed.
for watcher_pid in $(orient_watcher_pids "$pile" "$persona"); do
    if orient_watcher_is_stale "$watcher_pid"; then
        kill "$watcher_pid" 2>/dev/null || true
    fi
done

watcher_pids=$(orient_live_watcher_pids "$pile" "$persona")

persona_shell=$(printf '%s' "$persona" | sed "s/'/'\\\\''/g")
pile_shell=$(printf '%s' "$pile" | sed "s/'/'\\\\''/g")
wrapper_shell=$(printf '%s' "$wrapper" | sed "s/'/'\\\\''/g")
thread_shell=$(printf '%s' "$thread" | sed "s/'/'\\\\''/g")
if [ -n "$watcher_pids" ]; then
    printf '%s\n' \
        "ORIENT WATCHER ARMED for $persona on $pile (PID(s): $(printf '%s' "$watcher_pids" | tr '\n' ' ' | sed 's/ $//'))." \
        'Do not launch a competing watcher. The primary/root agent should retain and poll' \
        'its existing long-running exec session; subagents must leave it alone. If this' \
        'window cannot access that session, hand ownership off explicitly rather than' \
        'killing a watcher whose live owner cannot be identified safely.'
elif [ -n "$thread" ]; then
    printf '%s\n' \
        'ORIENT WATCHER FIRST (primary/root Codex agent): before substantive work, launch' \
        "sh '$wrapper_shell' '$thread_shell' --pile '$pile_shell' --persona '$persona_shell'" \
        'through a long-running exec call, retain its session id, and poll it during long' \
        'work and before ending a turn. This wrapper queues one Orient notification' \
        'back to this thread. On successful delivery, process the news and rearm it.' \
        'While it retries delivery, retain the session and do not start another wait. Subagents must not' \
        "start competing watchers for $persona."
else
    echo 'Orient watcher could not be armed: the hook has no Codex session id. Do not guess a destination thread.'
fi
