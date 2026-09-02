#!/bin/bash
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/stranded-work-test.XXXXXX")
trap 'rm -rf "$fixture"' EXIT

workspace="$fixture/workspace"
cached="$fixture/cache/faculties/habit"
mkdir -p "$workspace/faculties" "$workspace/repo" "$cached"

# A real Faculties checkout is the workspace marker used by the carried script.
git -C "$workspace/faculties" init -q
git -C "$workspace/repo" init -q
printf 'before\n' > "$workspace/repo/tracked"
git -C "$workspace/repo" add tracked
git -C "$workspace/repo" -c user.name=test -c user.email=test@example.invalid \
  commit -qm initial
printf 'after\n' >> "$workspace/repo/tracked"

# Model Habit materialization: the executable no longer resides below
# <workspace>/faculties/scripts, but its cwd remains the pile directory.
cp "$here/stranded-work.sh" "$cached/stranded-work"
chmod +x "$cached/stranded-work"
if ! (cd "$workspace" && STRANDED_MINUTES=0 "$cached/stranded-work" --due); then
  echo "carried script did not inspect its workspace cwd" >&2
  exit 1
fi

echo "stranded-work carried-script fixture passed"
