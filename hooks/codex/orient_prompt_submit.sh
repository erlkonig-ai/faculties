#!/bin/sh
set -eu

# Drain Codex's hook-event JSON. The poll itself needs no prompt contents.
cat >/dev/null

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
faculties_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
project_dir=$(CDPATH= cd -- "$faculties_dir/.." && pwd)
release_root=${FACULTIES_RELEASE_ROOT:-"$HOME/.local/lib/faculties"}
orient="$release_root/current/bin/orient"
pile=${ORIENT_PILE:-"$project_dir/self.pile"}
persona=${ORIENT_PERSONA:-${PERSONA:-}}

case "$pile" in
    /*) ;;
    *) echo 'Orient hook disabled: ORIENT_PILE must be an absolute path.' >&2; exit 0 ;;
esac

# Hooks are coordination aids, not a reason to break prompt submission when a
# fresh checkout has not built faculties yet.
if [ -z "$persona" ] || [ ! -x "$orient" ] || [ ! -f "$pile" ] || ! command -v jq >/dev/null 2>&1; then
    exit 0
fi

# Codex currently fires UserPromptSubmit for root and subagents without
# exposing which one fired it. Peek is therefore essential: a worker can see
# the same news, but can never record it as presented for the root persona.
news=$(
    "$orient" --pile "$pile" --persona "$persona" poll --peek 2>/dev/null
) || exit 0

if [ -z "$news" ]; then
    exit 0
fi

jq -n --arg news "$news" '{
  "hookSpecificOutput": {
    "hookEventName": "UserPromptSubmit",
    "additionalContext": (
      "=== ORIENT NEWS (poll --peek) ===\n" +
      $news +
      "\n\nProcess relevant news during this turn. Peek recorded no Presented facts; the blocking root watcher still owns that responsibility."
    )
  }
}'
