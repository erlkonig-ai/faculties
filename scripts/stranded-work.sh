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
# Prefer the evaluator's workspace cwd when this script has been materialized
# from its carried blob; otherwise derive the root from the source checkout.
# An absolute operator path would (a) work on exactly one machine and (b) carry a
# protected term into a public repository -- the pre-push guard refused this file
# on its first push for exactly that, and was right to.
_self=${BASH_SOURCE[0]:-$0}
_here=$(cd "$(dirname "$_self")" && pwd)
if [ -n "${STRANDED_ROOT:-}" ]; then
  ROOT=$STRANDED_ROOT
elif [ -e "$PWD/faculties/.git" ]; then
  # Habit carries this script as a blob and materializes it in a content-addressed
  # cache. In that case its source path says nothing about the workspace, while
  # the evaluator deliberately runs it from the directory containing the pile.
  ROOT=$PWD
else
  ROOT=$(cd "$_here/../.." && pwd)
fi
DUE_ONLY=0
[ "${1:-}" = "--due" ] && DUE_ONLY=1

found=0
report=""

# In --due mode the ANSWER is a boolean, so stop at the first finding. The full
# report costs ~6s across 75 trees; the question "is there anything" usually
# costs a fraction of that, and it is the one asked every 60 seconds.
note() {
  found=1
  report="${report}$1"$'\n'
  [ "$DUE_ONLY" = "1" ] && exit 0
}

# GNU `stat -f` is not the BSD formatter: it succeeds and prints filesystem
# metadata, so an `A || B` probe silently feeds prose into the age arithmetic.
# Try the GNU spelling first and accept only the numeric value both variants
# promise before falling back to BSD/macOS.
mtime() {
  local value
  value=$(stat -c %Y "./$1" 2>/dev/null) || value=$(stat -f %m "./$1" 2>/dev/null) || return 1
  case "$value" in ''|*[!0-9]*) return 1 ;; esac
  printf '%s\n' "$value"
}

# A WORKTREE's `.git` is a FILE, not a directory. Testing `-d` skipped all 33 of
# them here against 42 real repositories -- a 44% blind spot in exactly the
# artifact class this file exists for. Worktrees are also the only place a
# DETACHED HEAD can hide, and a detached worktree is invisible to every
# branch-based check by construction: there is no branch to be unmerged.
for repo in "$ROOT"/*/; do
  [ -e "$repo/.git" ] || continue
  name=$(basename "$repo")
  cd "$repo" 2>/dev/null || continue

  # Worktrees SHARE the parent repository's refs, so running the branch checks in
  # each one would report the same branch once per worktree. Give them only the
  # checks that are theirs: what HEAD is doing, and what is uncommitted in them.
  is_worktree=0
  [ -f "$repo/.git" ] && is_worktree=1

  if [ "$is_worktree" = "1" ]; then
    wdirty=$(git status --porcelain --untracked-files=no 2>/dev/null | wc -l | tr -d ' ')
    [ "${wdirty:-0}" -gt 0 ] && note "  $name (worktree): $wdirty tracked file(s) uncommitted"
    # A detached worktree looks healthy and has silently stopped following its
    # branch. On 2026-08-26 both Sparks sat detached at a109514 -- correct
    # CONTENT, no attachment -- so `git pull` did nothing and they fell six
    # commits behind without a symptom. `git checkout <sha>` is the usual cause;
    # `git checkout -B <name> <sha>` is what was meant.
    if ! git rev-parse --git-dir >/dev/null 2>&1; then
      # ORPHANED, not detached: the .git file points at worktree metadata the
      # parent repository has already pruned, so this is a dead directory
      # wearing a worktree's clothes. `git worktree prune` removed the record
      # and left the tree. It reports as detached to any naive check because
      # every git query against it fails identically.
      note "  $name (worktree): ORPHANED -- gitdir is gone, run 'git worktree prune' in the parent and remove this directory"
    elif [ -z "$(git branch --show-current 2>/dev/null)" ]; then
      note "  $name (worktree): DETACHED at $(git log --oneline -1 2>/dev/null | cut -c1-40)"
    fi
    continue
  fi

  # 1. Uncommitted work. Ignores untracked build noise; tracked edits only,
  #    because an untracked file is usually a log and a tracked edit is usually
  #    a thought someone had.
  # AGE IT. Work uncommitted for ten minutes is work in progress; work
  # uncommitted for six hours has been forgotten. Flagging both makes the
  # detector fire continuously while someone is editing, which is the noise
  # failure -- a detector you learn to ignore is a detector that is off.
  # STRANDED_MINUTES sets the line; the default assumes a session boundary.
  mins=${STRANDED_MINUTES:-90}
  dirty=$(git status --porcelain --untracked-files=no 2>/dev/null | wc -l | tr -d ' ')
  if [ "${dirty:-0}" -gt 0 ]; then
    oldest=$(git status --porcelain --untracked-files=no 2>/dev/null | awk '{print $NF}' \
             | while read -r f; do [ -e "$f" ] && mtime "$f"; done \
             | sort -n | head -1)
    if [ -n "$oldest" ]; then
      agem=$(( ( $(date +%s) - oldest ) / 60 ))
      [ "$agem" -ge "$mins" ] && note "  $name: $dirty tracked file(s) uncommitted, oldest ${agem}m"
    fi
  fi

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
    # `archive-*`/`archive/*` is a CLAIM, and it carries an obligation: naming a
    # branch this way asserts that its bytes are preserved somewhere durable that
    # is NOT this checkout, and that a note somewhere says where. It exists
    # because a branch can be legitimately unpushable -- 2026-08-26, playground's
    # Teams-daemon tip could not go to `origin` because posture correctly found a
    # protected term in the range, so it was bundled into the pile (which
    # replicates to three machines) and given a wiki fragment. Without this case
    # the detector would nag forever about a thing that was already handled, and a
    # detector that cries wolf on resolved work teaches you to skim it.
    case "$br" in archive-*|archive/*) continue ;; esac
    n=$(git rev-list --count "$br" --not --remotes 2>/dev/null || echo 0)
    [ "${n:-0}" -gt 0 ] && note "  $name: branch '$br' has $n commit(s) on no remote"
  done

  # 2b. EVERY BRANCH OWES A DISPOSITION. A branch is fine if it is one of three
  #     things, and needs a decision if it is none of them:
  #       merged into main and deleted  -- the work landed
  #       named `negative-*`            -- a measured dead end, kept deliberately
  #       named `archive-*`/`archive/*` -- preserved deliberately; see below
  #       under a live worktree         -- someone is working in it
  #     Anything else is the ambiguous middle, and the ambiguous middle is where
  #     everything stranded on 2026-08-26 was living. The point is not to delete
  #     it; it is that "I have not decided" stops being a silent option.
  wt_branches=$(git worktree list --porcelain 2>/dev/null | sed -n 's/^branch refs\/heads\///p' | tr '\n' '|')
  # for-each-ref carries the committer date, so this is ONE call rather than a
  # `git log` per branch. That mattered: the per-branch form pushed a detector
  # that runs every 60 seconds from 4.4s to 5.6s.
  now=$(date +%s)
  git for-each-ref --format='%(refname:short) %(committerdate:unix)' refs/heads 2>/dev/null | while read -r br when; do
    case "$br" in main|master|negative-*|negative/*|archive-*|archive/*) continue ;; esac
    case "|$wt_branches" in *"|$br|"*) continue ;; esac   # a live worktree is a claim
    age=$(( (now - ${when:-$now}) / 86400 ))
    [ "$age" -ge 2 ] && echo "  $name: branch '$br' owes a disposition (${age}d idle) -- merge+delete, rename negative-*/archive-*, or claim it"
  done > /tmp/.sw_disp.$$ 2>/dev/null
  if [ -s /tmp/.sw_disp.$$ ]; then found=1; report="${report}$(cat /tmp/.sw_disp.$$)"$'\n'; fi
  rm -f /tmp/.sw_disp.$$

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
