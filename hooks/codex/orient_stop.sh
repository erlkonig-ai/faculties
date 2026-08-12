#!/bin/sh
set -eu

input=$(cat)
persona=${ORIENT_PERSONA:-${PERSONA:-}}

if [ -z "$persona" ]; then
    printf '%s\n' '{"continue":true,"systemMessage":"Orient hook disabled: set ORIENT_PERSONA or PERSONA to arm a watcher."}'
    exit 0
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/orient_process.sh"
faculties_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
project_dir=$(CDPATH= cd -- "$faculties_dir/.." && pwd)
release_root=${FACULTIES_RELEASE_ROOT:-"$HOME/.local/lib/faculties"}
orient="$release_root/current/bin/orient"
pile=${ORIENT_PILE:-"$project_dir/self.pile"}
case "$pile" in
    /*) ;;
    *) printf '%s\n' '{"continue":true,"systemMessage":"Orient hook disabled: ORIENT_PILE must be an absolute path."}'; exit 0 ;;
esac
orient=$(orient_canonical_path "$orient" "$(pwd -P)" 2>/dev/null || printf '%s\n' "$orient")

watcher_pids=$(orient_live_watcher_pids "$pile" "$persona")
if [ -n "$watcher_pids" ]; then
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

if command -v jq >/dev/null 2>&1; then
    jq -n \
      --arg persona "$persona" \
      --arg orient_shell "$(printf '%s' "$orient" | sed "s/'/'\\\\''/g")" \
      --arg pile_shell "$(printf '%s' "$pile" | sed "s/'/'\\\\''/g")" \
      --arg persona_shell "$(printf '%s' "$persona" | sed "s/'/'\\\\''/g")" '{
      decision: "block",
      reason: (
        "The " + $persona + " orient watcher is not armed. Poll the previous watcher session for pending news, process anything it reported, then launch \u0027" + $orient_shell + "\u0027 --pile \u0027" + $pile_shell + "\u0027 --persona \u0027" + $persona_shell + "\u0027 wait through a long-running exec call and retain its session id before finishing."
      )
    }'
else
    printf '%s\n' '{"decision":"block","reason":"The configured Orient watcher is not armed. Poll pending news, process it, then launch Orient wait through a long-running exec call and retain its session id before finishing."}'
fi
