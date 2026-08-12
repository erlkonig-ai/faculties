#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/orient_process.sh"

tab=$(printf '\t')
assert_fields() {
    command_line=$1
    expected_persona=$2
    expected_pile=$3
    fields=$(orient_parse_wait_command "$command_line")
    actual_persona=${fields%%"$tab"*}
    actual_pile=${fields#*"$tab"}
    [ "$actual_persona" = "$expected_persona" ] || {
        echo "persona mismatch: $command_line" >&2
        exit 1
    }
    [ "$actual_pile" = "$expected_pile" ] || {
        echo "pile mismatch: $command_line" >&2
        exit 1
    }
}

assert_rejected() {
    if orient_parse_wait_command "$1" >/dev/null 2>&1; then
        echo "unexpected match: $1" >&2
        exit 1
    fi
}

assert_fields '/opt/faculties/orient --pile /tmp/self.pile --persona agent wait' agent /tmp/self.pile
assert_fields '/opt/faculties/orient --persona agent --pile /tmp/self.pile wait' agent /tmp/self.pile
assert_fields '/opt/faculties/orient --persona=agent --pile=/tmp/self.pile wait' agent /tmp/self.pile
assert_fields '/opt/faculties/orient wait --pile=/tmp/self.pile --persona agent' agent /tmp/self.pile
assert_fields '/opt/faculties/orient --key /tmp/key --persona=agent wait' agent ''
assert_rejected '/opt/faculties/orient --persona agent --pile /tmp/self.pile show'

fixture_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd -P)
expected="$fixture_dir/Cargo.toml"
actual=$(orient_canonical_path './Cargo.toml' "$fixture_dir")
[ "$actual" = "$expected" ] || {
    echo "relative path mismatch: expected $expected, got $actual" >&2
    exit 1
}

if orient_watcher_is_stale "$$"; then
    echo 'the live test shell was classified as stale' >&2
    exit 1
fi
orient_watcher_is_stale 99999999 || {
    echo 'a missing process was classified as live' >&2
    exit 1
}

echo 'orient process matching tests passed'
