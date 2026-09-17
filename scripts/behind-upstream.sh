#!/bin/bash
# Is any checkout on THIS machine behind its upstream?
#
#   behind-upstream.sh          fetch every checkout we work in, report what is behind
#   behind-upstream.sh --all    include read-only vendor clones we never commit to
#   behind-upstream.sh --quiet  print nothing when everything is current
#
# Output is terse on purpose. It is read by a habit nudge every time something
# falls behind, so every line of standing explanation would be paid for again on
# each firing. The reasoning lives in this header, where it is read once by a
# person and never by the loop.
#
# Exit 0 means something is behind, so it serves directly as a habit condition:
#   habit add behind-upstream --when "when @script" --script <this file>
#
# WHY THIS EXISTS. On 2026-09-17 I asserted three things from stale checkouts in
# one afternoon, each with evidence, each wrong: that a binary existed nowhere
# (28 commits carrying it landed on origin while I searched), that a one-line
# guard was missing (already upstream), and that the faculties workspace did not
# compile (sky's checkout was 31 commits behind a tree where it was fixed, and I
# had not fetched it once that session).
#
# Being behind has NO LOCAL SYMPTOM. A stale checkout looks exactly like a
# current one, which is why a rule did not save me: I had written "fetch before
# asserting anything is absent" into a subagent's brief hours earlier and still
# did not do it. A condition with no felt sense attached gets checked
# mechanically or not at all.
#
# IT FETCHES, AND THAT IS THE WHOLE POINT. The interesting case is work a
# colleague merged, which does not exist locally until a fetch brings the ref
# over. An earlier draft hid the fetch behind a --refresh/--due split so the
# habit check could be "fast"; nothing ever called --refresh, so the fast path
# read a number that could never change -- a perfectly optimised answer to a
# question no longer being asked. A check that cannot observe what it reports is
# worse than no check, because it reports all-clear.
#
# COST, and why no cache is needed. `when` predicates are gated by a one-hour
# cooldown that Orient tests BEFORE spawning the command (faculties
# src/habits.rs:1807), so a completed habit costs nothing until the hour is up.
# Between completions the predicate runs on Orient's 60 s tick. Measured on this
# box 2026-09-17, warm: 0.6-2.2 s per repo, ~3.5 s of CPU for the whole sweep.
# Fetches run concurrently below, so the wall clock is the slowest single repo
# rather than their sum -- a serial version of this same sweep took 35 s, which
# is what made the fetch look unaffordable when it is not.
#
# SCOPE IS OUR OWN REPOS, by a test rather than a list. A checkout counts when
# recent history carries a commit from one of us. That is not a proxy for
# ownership; it is the question itself -- JP's reason for fetching is "to make
# sure that we notice work merged by someone else", and a repo where none of us
# has ever committed has no such work to miss. It also removes the noise that
# would otherwise make this habit useless: the vendored clones of aruna, fluree
# and iroh sit thousands of commits behind their upstreams permanently and by
# design, and a signal that is always on is not a signal. `--all` shows them.
#
# THIS MACHINE ONLY, deliberately. Each window runs its own box and minds its own
# checkouts. Reaching other hosts would need ssh, which turns a local check into
# a distributed one that fails in more ways than it catches.
#
# WHAT IS COMPARED, and why it excludes the clock. `stranded-work.sh` once fired
# four times in an hour about work nobody had touched, because its output carried
# an idle-day count and waiting alone minted a new identity. The only thing
# printed here is a commit count, which changes when upstream moves and at no
# other time.

set -uo pipefail

_self=${BASH_SOURCE[0]:-$0}
_here=$(cd "$(dirname "$_self")" && pwd)
if [ -n "${BEHIND_ROOT:-}" ]; then
  ROOT=$BEHIND_ROOT
elif [ -e "$PWD/faculties/.git" ]; then
  # Habit carries this script as a blob and materializes it in a content-addressed
  # cache, so its own path says nothing about the workspace; the evaluator runs it
  # from the directory holding the pile.
  ROOT=$PWD
else
  ROOT=$(cd "$_here/../.." && pwd)
fi

# One unreachable remote must not stall the sweep. A timed-out fetch leaves the
# previous remote-tracking refs in place, so that repo is still reported from
# what is already known rather than dropped silently.
FETCH_TIMEOUT=${BEHIND_FETCH_TIMEOUT:-25}
# Author or committer addresses that mean "one of us". Extended regex.
OURS=${BEHIND_OURS:-bultmann|erlkonig|triblespace}
# How far back to look for one of our commits. Deep enough to survive a stretch
# of vendor merges, shallow enough to stay a few milliseconds.
OURS_DEPTH=${BEHIND_OURS_DEPTH:-300}

ALL=0
QUIET=0
for arg in "$@"; do
  case "$arg" in
    --all) ALL=1 ;;
    --quiet) QUIET=1 ;;
    --help|-h) sed -n '2,8p' "$_self"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

work=$(mktemp -d) || exit 2
trap 'rm -rf "$work"' EXIT

skipped=0
examined=0
for dot in $(find "$ROOT" -maxdepth 2 -name .git -print 2>/dev/null | sort); do
  # A .git FILE is a linked worktree or a dead alias. Worktrees share their
  # parent's remote-tracking refs, so fetching one repeats the same network call
  # against the same remote.
  [ -d "$dot" ] || continue
  repo=$(dirname "$dot")
  name=${repo#"$ROOT"/}

  # No upstream is not "behind" -- it is a different finding, and
  # stranded-work.sh already reports branches no remote has seen.
  upstream=$(git -C "$repo" rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null) || continue

  # Captured first rather than piped into grep. Under `pipefail`, `grep -q`
  # exits on the FIRST match and git dies of SIGPIPE, so the pipeline reports
  # failure precisely when the match succeeded -- and the repos it silently
  # dropped were the ones whose newest commits are ours, i.e. exactly the ones
  # this script exists to watch. It read as a clean sweep.
  authors=$(git -C "$repo" log -n "$OURS_DEPTH" --format='%ae %ce' HEAD 2>/dev/null)
  if [ "$ALL" = "0" ] && ! grep -qEi "$OURS" <<<"$authors"; then
    skipped=$(( skipped + 1 ))
    continue
  fi
  examined=$(( examined + 1 ))

  # Concurrent, because the sweep is network latency rather than work.
  #
  # A REPO WE COULD NOT COMPARE MUST NOT READ AS CURRENT. Both of the ways this
  # can fail are silent by nature: a fetch that times out leaves the old
  # tracking ref in place and rev-list happily counts against WEEK-OLD data,
  # and a rev-list that fails outright (force-pushed upstream, ref gone) just
  # returns nothing. Either one used to produce no output, which the reporting
  # below could not tell apart from "this repo is current" -- so a box with no
  # network at all would report "all current" about every checkout on it, with
  # a confident count to back it up. Each failure now writes its own line.
  (
    key=${name//\//_}
    fetched=1
    timeout "$FETCH_TIMEOUT" git -C "$repo" fetch --quiet "${upstream%%/*}" 2>/dev/null || fetched=0
    # Only what upstream has and we do not. Commits of ours that upstream lacks
    # are stranded-work.sh's question, not this one.
    behind=$(git -C "$repo" rev-list --count "HEAD..$upstream" 2>/dev/null)
    # Keyed on the repo, not $$ -- inside a subshell $$ is still the PARENT
    # shell's pid, so every branch of the fan-out would write the same file.
    if [ -z "$behind" ]; then
      printf '%s\tcannot compare against %s\n' "$name" "$upstream" > "$work/p_$key"
    elif [ "$fetched" = "0" ]; then
      printf '%s\tfetch failed; %s behind %s is from STALE refs\n' \
        "$name" "$behind" "$upstream" > "$work/p_$key"
    elif [ "$behind" != "0" ]; then
      printf '%s\t%s\t%s\n' "$name" "$behind" "$upstream" > "$work/b_$key"
    fi
  ) &
done
wait

lines=$(cat "$work"/b_* 2>/dev/null | sort)
problems=$(cat "$work"/p_* 2>/dev/null | sort)

# Examining nothing is not an all-clear. If ROOT is wrong, or a machine lays its
# checkouts out differently, or the authorship test matches none of them, the
# sweep finds zero repos and every one of them could be a year behind. Reporting
# "all current" there would be this script committing the exact error it exists
# to catch, on a box where nobody would think to question it. So a sweep that
# examined nothing is DUE, with a different message.
if [ "$examined" = "0" ]; then
  echo "examined NOTHING under $ROOT -- this is not an all-clear."
  echo "No checkout there has both an upstream and a commit matching: $OURS"
  echo "Set BEHIND_ROOT to this machine's workspace, or BEHIND_OURS to its authors."
  exit 0
fi

# A problem is due on its own. Not knowing is not good news.
if [ -n "$problems" ]; then
  echo "could NOT check:"
  printf '%s\n' "$problems" | while IFS=$'\t' read -r name why; do
    printf '  %-24s %s\n' "$name" "$why"
  done
fi

if [ -z "$lines" ]; then
  if [ -n "$problems" ]; then
    exit 0
  fi
  [ "$QUIET" = "0" ] && echo "all current ($examined checked)"
  exit 1
fi

echo "behind upstream:"
printf '%s\n' "$lines" | while IFS=$'\t' read -r name behind upstream; do
  printf '  %-24s %5s  %s\n' "$name" "$behind" "$upstream"
done
# The skipped count stays, short. It is the one guard against reading a narrow
# sweep as a complete one, which is the failure this whole script exists to stop.
[ "$skipped" -gt 0 ] && echo "($skipped vendor clone(s) skipped; --all to include)"
exit 0
