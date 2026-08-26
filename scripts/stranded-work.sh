#!/bin/bash
# Is any work stranded? -- the cheap half of a two-part answer.
#
#   stranded-work.sh --due     exit 0 if something is stranded, 1 if not
#   stranded-work.sh           print what it found
#
# WHY THIS EXISTS. On 2026-08-26 an audit found: a branch that was the pivot of
# the whole project sitting unmerged and unbuildable for weeks; 19 commits alive
# on one box only; three instruments uncommitted in a scratch tree; one commit on
# no remote at all; 56 worktrees across two machines; and 35 branches already
# merged and never deleted. None of it was forgotten -- the commit messages were
# excellent. It was INVISIBLE, because a branch list cannot tell finished work
# from unfinished work, and a branch list is what people navigate by.
#
# `work-ledger-grooming` already asks the right question every 7 days. Seven days
# is far too slow for a system that produced 56 worktrees in one day, and its own
# audit declares two blind spots in its own output: "remote freshness: NOT CHECKED
# (this audit never fetches)" and "live-process custody: NOT CHECKED". Both are
# exactly where the stranded work was hiding.
#
# So this is deliberately the CHEAP half. `orient` re-evaluates habit conditions
# every 60 seconds (orient.rs:1740), so `--due` must cost almost nothing: it does
# NOT fetch, does NOT ssh, and does NOT walk history. It answers "is there
# something to look at" in milliseconds. The expensive, definitive answer is
# `worktree-audit.py`, which the nudge sends you to once this says yes.
#
# It reports on TRANSITION, not continuously -- `newly_due` handles that -- so a
# thing you have decided to leave alone will not nag once you mark the habit done.

set -uo pipefail
# Derive the workspace root from this script's own location rather than hardcoding
# it. This file lives at <root>/faculties/scripts/, so two parents up is the root.
# An absolute operator path would (a) work on exactly one machine and (b) carry a
# protected term into a public repository -- the pre-push guard refused this file
# on its first push for exactly that, and was right to.
_self=${BASH_SOURCE[0]:-$0}
_here=$(cd "$(dirname "$_self")" && pwd)
ROOT=${STRANDED_ROOT:-$(cd "$_here/../.." && pwd)}
DUE_ONLY=0
[ "${1:-}" = "--due" ] && DUE_ONLY=1

found=0
report=""

note() { found=1; report="${report}$1"$'\n'; }

for repo in "$ROOT"/*/; do
  [ -d "$repo/.git" ] || continue
  name=$(basename "$repo")
  cd "$repo" 2>/dev/null || continue

  # 1. Uncommitted work. Ignores untracked build noise; tracked edits only,
  #    because an untracked file is usually a log and a tracked edit is usually
  #    a thought someone had.
  dirty=$(git status --porcelain --untracked-files=no 2>/dev/null | wc -l | tr -d ' ')
  [ "${dirty:-0}" -gt 0 ] && note "  $name: $dirty tracked file(s) uncommitted"

  # 2. Local commits on no remote. This is the one that loses work outright, and
  #    it is the check `worktree-audit.py` declares it does not do.
  #    --remotes is a LOCAL question about refs already fetched; that is a real
  #    limitation and the nudge says so, because a stale remote-ref set produced
  #    two false "this is unpushed" alarms on the day this was written.
  # A repo with NO remote is local BY DESIGN, not stranded -- every commit in it
  # is trivially "on no remote" and reporting them is noise. The first version of
  # this file did exactly that and cried wolf on 5 of 7 repositories, which is a
  # worse failure than not checking: a detector you learn to ignore is a detector
  # that is off. Ask whether there is anywhere for the work to GO before asking
  # whether it went there.
  if [ "$(git remote 2>/dev/null | wc -l | tr -d ' ')" -eq 0 ]; then continue; fi

  for br in $(git for-each-ref --format='%(refname:short)' refs/heads 2>/dev/null); do
    n=$(git rev-list --count "$br" --not --remotes 2>/dev/null || echo 0)
    [ "${n:-0}" -gt 0 ] && note "  $name: branch '$br' has $n commit(s) on no remote"
  done

  # 3. Merged and not deleted. Cheap, and it is the husk that made finished work
  #    look unfinished all day.
  base=$(git symbolic-ref -q --short refs/remotes/origin/HEAD 2>/dev/null || echo origin/main)
  # NOTE: never `$(grep -c ... || echo 0)`. `grep -c` prints 0 AND exits 1 when it
  # matches nothing, so the `||` fires and the substitution becomes the two-line
  # string "0\n0", which every numeric test then rejects with "integer expression
  # expected". This project hit that on 2026-08-26 in tp-probe.sh -- where it made
  # a clean-RoCE result read as "transport UNKNOWN" -- and the author of THIS file
  # reproduced it the same evening. Capture, then default.
  stale=$(git branch -r --merged "$base" 2>/dev/null | grep -c '^  origin/')
  stale=${stale:-0}
  [ "$stale" -gt 3 ] && note "  $name: $stale merged branch(es) not deleted"
done

if [ "$DUE_ONLY" = "1" ]; then exit $((1 - found)); fi
if [ "$found" = "1" ]; then printf 'stranded work:\n%s' "$report"; else echo "nothing stranded"; fi
exit 0
