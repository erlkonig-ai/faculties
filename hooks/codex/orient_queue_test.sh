#!/bin/sh
set -eu

# This executable doubles as a fake Codex. Tests never contact an account,
# model, real queue, pile, watcher, or user hook configuration.
if [ "${0##*/}" = codex ]; then
    printf 'called\n' >> "$test_case/calls"
    printf '%s\000' "$@" > "$test_case/argv"
    printf 'queue client stdout must not escape\n'
    echo 'queue client diagnostic' >&2
    exit "${test_queue_status:-0}"
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/orient-queue-test.XXXXXXXX")
trap 'rm -rf "$fixture"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$fixture/bin"
ln -s "$script_dir/orient_queue_test.sh" "$fixture/bin/codex"
export PATH="$fixture/bin:$PATH"
thread='exact-thread with "quotes"'
report='News: café, quotes " and apostrophes '\'' stay data.
$(touch "$test_case/INJECTED") `touch "$test_case/INJECTED"`
Last line.

'
export test_queue_status=0

new_case() {
    test_case="$fixture/$1"
    export test_case
    mkdir "$test_case"
}
run_callback() {
    printf '%s' "$report" | sh "$script_dir/orient_queue.sh" "$thread" \
        > "$test_case/stdout" 2> "$test_case/stderr"
}

new_case success
run_callback
printf '%s\000' queue --thread "$thread" --message "$report" > "$test_case/expected"
cmp "$test_case/expected" "$test_case/argv"
[ "$(wc -l < "$test_case/calls" | tr -d ' ')" = 1 ]
[ ! -s "$test_case/stdout" ]
[ ! -e "$test_case/INJECTED" ]
grep -q 'queue client diagnostic' "$test_case/stderr"

new_case failure
test_queue_status=7
if run_callback; then
    echo 'failed callback unexpectedly succeeded' >&2
    exit 1
else
    [ "$?" = 7 ]
fi
[ "$(wc -l < "$test_case/calls" | tr -d ' ')" = 1 ]
[ ! -s "$test_case/stdout" ]
test_queue_status=0

new_case empty
report=''
if run_callback; then exit 1; else [ "$?" = 2 ]; fi
[ ! -e "$test_case/calls" ]

new_case missing-thread
if sh "$script_dir/orient_queue.sh" '' </dev/null > "$test_case/stdout" 2> "$test_case/stderr"; then
    exit 1
else
    [ "$?" = 2 ]
fi
[ ! -e "$test_case/calls" ]

echo 'orient queue callback tests passed'
