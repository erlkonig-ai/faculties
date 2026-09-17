#!/bin/sh
set -eu

# One delivery attempt for one complete UTF-8 report. No watcher, spool,
# retry, stdout report, or shell interpretation of the report lives here.
if [ "$#" -ne 1 ] || [ -z "$1" ]; then
    echo 'Usage: orient_queue.sh THREAD (report on stdin)' >&2
    exit 2
fi

# Command substitution normally strips trailing newlines. The final sentinel
# preserves them, and removing exactly that sentinel restores the input.
report=$(cat && printf .) || exit $?
report=${report%.}
if [ -z "$report" ]; then
    echo 'Orient queue callback requires a nonempty report' >&2
    exit 2
fi
exec codex queue --thread "$1" --message "$report" >/dev/null
