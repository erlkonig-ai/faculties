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

# A canonical custody pile is not a source workspace. The carried command must
# ask for a root, not mistake its cache ancestry for a clean workspace.
custody="$fixture/custody"
mkdir "$custody"
set +e
(cd "$custody" && env -u STRANDED_ROOT "$cached/stranded-work" --due) > "$fixture/missing-root" 2>&1
code=$?
set -e
[ "$code" = 126 ] || { echo "missing workspace root was not indeterminate" >&2; exit 1; }
(cd "$custody" && STRANDED_ROOT="$workspace" STRANDED_MINUTES=0 "$cached/stranded-work" --due)
git -C "$workspace/repo" checkout -- tracked

# Nested independent, detached clones are not in the main repository's
# worktree registry. A cached remote ref witnesses only the original commit.
nested="$workspace/.worktrees/cohort/core"
mkdir -p "$(dirname "$nested")"
git clone -q "$workspace/repo" "$nested"
git -C "$nested" checkout -q --detach
printf 'private\n' >> "$nested/tracked"
git -C "$nested" add tracked
git -C "$nested" -c user.name=test -c user.email=test@example.invalid commit -qm private
STRANDED_ROOT="$workspace" "$cached/stranded-work" > "$fixture/report"
grep -q '.worktrees/cohort/core: detached HEAD has 1 commit(s) on no cached remote' "$fixture/report"
STRANDED_ROOT="$workspace" "$cached/stranded-work" --due

# Symlink aliases must not double report; target trees must not be traversed.
ln -s "$nested" "$workspace/alias"
mkdir "$workspace/target-private"
git clone -q "$workspace/repo" "$workspace/target-private/ignored"
git -C "$workspace/target-private/ignored" checkout -q --detach
STRANDED_ROOT="$workspace" "$cached/stranded-work" > "$fixture/report"
! grep -q 'alias\|target-private' "$fixture/report"
[ "$(grep -c 'detached HEAD has' "$fixture/report")" = 1 ]

# Shared refs are checked once, while each worktree retains its custody check.
git -C "$nested" switch -qc private
git -C "$nested" worktree add -q -b sibling "$workspace/.worktrees/linked" HEAD
STRANDED_ROOT="$workspace" "$cached/stranded-work" > "$fixture/report"
[ "$(grep -c "branch 'private' has 1" "$fixture/report")" = 1 ]
[ "$(grep -c "branch 'sibling' has 1" "$fixture/report")" = 1 ]

# main and the symbolic remote HEAD are not abandoned branches. An actual
# merged remote branch is named accurately as cached, not remotely verified.
base=$(git -C "$nested" rev-parse refs/remotes/origin/HEAD 2>/dev/null || git -C "$nested" rev-parse refs/remotes/origin/master)
git -C "$nested" update-ref refs/remotes/origin/main "$base"
git -C "$nested" symbolic-ref refs/remotes/origin/HEAD refs/remotes/origin/main
STRANDED_ROOT="$workspace" "$cached/stranded-work" > "$fixture/report"
! grep -q 'merged cached remote' "$fixture/report"
git -C "$nested" update-ref refs/remotes/origin/finished "$base"
STRANDED_ROOT="$workspace" "$cached/stranded-work" > "$fixture/report"
grep -q '1 merged cached remote branch ref(s)' "$fixture/report"

set +e
STRANDED_ROOT="$custody" "$cached/stranded-work" --due > "$fixture/empty-root" 2>&1
code=$?
set -e
[ "$code" = 126 ] || { echo "empty workspace was not indeterminate" >&2; exit 1; }

echo "stranded-work discovery fixtures passed"
