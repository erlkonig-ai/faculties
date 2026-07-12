#!/bin/sh
set -eu

# Drain Codex's hook-event JSON. The poll itself needs no prompt contents.
cat >/dev/null

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
faculties_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
project_dir=$(CDPATH= cd -- "$faculties_dir/.." && pwd)
orient="$faculties_dir/target/release/orient"
pile="$project_dir/self.pile"

# Hooks are coordination aids, not a reason to break prompt submission when a
# fresh checkout has not built faculties yet.
if [ ! -x "$orient" ] || [ ! -f "$pile" ] || ! command -v jq >/dev/null 2>&1; then
    exit 0
fi

# Codex currently fires UserPromptSubmit for root and subagents without
# exposing which one fired it. Peek is therefore essential: a worker can see
# the same news, but can never advance or initialize liora-gpt's checkpoint.
news=$(
    "$orient" --pile "$pile" --persona liora-gpt poll --peek 2>/dev/null
) || exit 0

if [ -z "$news" ]; then
    exit 0
fi

jq -n --arg news "$news" '{
  "hookSpecificOutput": {
    "hookEventName": "UserPromptSubmit",
    "additionalContext": (
      "=== COLONY NEWS (orient poll --peek) ===\n" +
      $news +
      "\n\nProcess relevant news during this turn. Peek did not consume the persona checkpoint; the blocking root watcher still owns that responsibility."
    )
  }
}'
