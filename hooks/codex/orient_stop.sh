#!/bin/sh
set -eu

input=$(cat)
watcher_pattern='[o]rient .*--persona[= ]liora-gpt .*wait'

if pgrep -f "$watcher_pattern" >/dev/null 2>&1; then
    printf '%s\n' '{"continue":true}'
    exit 0
fi

# Stop hooks get one automatic continuation. Do not create an infinite loop if
# the model cannot arm the watcher (missing binary, permissions, etc.); make the
# failure visible on the second stop and allow the turn to end.
if printf '%s' "$input" | grep -Eq '"stop_hook_active"[[:space:]]*:[[:space:]]*true'; then
    printf '%s\n' '{"continue":true,"systemMessage":"Orient watcher remains unarmed after the enforced retry; inspect the hook and faculty binary."}'
    exit 0
fi

printf '%s\n' '{"decision":"block","reason":"The liora-gpt orient watcher is not armed. Poll the previous watcher session for pending news, process anything it reported, then launch faculties/target/release/orient --pile ./self.pile --persona liora-gpt wait through a long-running exec call and retain its session id before finishing."}'
