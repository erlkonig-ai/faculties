#!/bin/bash
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
wrapper=${1:-"$here/rustc-expendable"}

# Inspect only our explicit sentinels, never the ambient compiler environment.
status=0
actual=$(env \
    'CARGO_BIN_EXE_files-capture=capture-sentinel' \
    'CARGO_BIN_EXE_viewer=viewer-sentinel' \
    "$wrapper" /bin/bash -c '
        set -e
        /usr/bin/printenv CARGO_BIN_EXE_files-capture
        /usr/bin/printenv CARGO_BIN_EXE_viewer
    ') || status=$?
expected=$(printf '%s\n' capture-sentinel viewer-sentinel)
if [[ "$status" != 0 || "$actual" != "$expected" ]]; then
    printf '%s\n' 'rustc-expendable lost a Cargo executable sentinel' >&2
    exit 1
fi

status=0
"$wrapper" /bin/bash -c 'exit 37' || status=$?
if [[ "$status" != 37 ]]; then
    printf '%s\n' 'rustc-expendable changed its child exit status' >&2
    exit 1
fi

if [[ "$(uname -s)" == Linux ]]; then
    score=$("$wrapper" /bin/bash -c \
        'IFS= read -r score < /proc/self/oom_score_adj; printf "%s\n" "$score"')
    if [[ "$score" != 1000 ]]; then
        printf '%s\n' 'rustc-expendable did not make its child OOM-expendable' >&2
        exit 1
    fi
fi

printf '%s\n' 'rustc-expendable sentinel, exit-status, and platform OOM checks passed'
