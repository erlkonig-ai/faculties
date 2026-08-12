#!/usr/bin/env bash
#
# Exercise the recipient-side bootstrap importer in a fresh pile. The
# distributable is the `bootstrap` binary with embedded declarative sources;
# no pre-signed pile artifact is produced.
#
# Usage:
#   cd faculties/bootstrap && ./build.sh
#
set -euo pipefail

BOOTSTRAP_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$BOOTSTRAP_DIR/.."
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/faculties-bootstrap.XXXXXX")"
PILE_PATH="$BUILD_DIR/self.pile"
KEY_PATH="$BUILD_DIR/self.key"
cleanup() {
  rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

echo "==> Pre-building bootstrap cohort"
cargo build --quiet --manifest-path="$REPO_ROOT/Cargo.toml" --release \
  --no-default-features --bin bootstrap --bin wiki --bin compass
BOOTSTRAP="$REPO_ROOT/target/release/bootstrap"
WIKI="$REPO_ROOT/target/release/wiki"
COMPASS="$REPO_ROOT/target/release/compass"

command -v trible >/dev/null || {
  echo "trible CLI is required to initialize the test signing identity" >&2
  exit 1
}
trible pile create "$PILE_PATH" >/dev/null
trible pile signing-key init "$PILE_PATH" --key "$KEY_PATH" >/dev/null
export PILE="$PILE_PATH"
export TRIBLESPACE_KEY="$KEY_PATH"

echo "==> Importing portable bootstrap"
FIRST="$("$BOOTSTRAP" import)"
BYTES_BEFORE=$(wc -c < "$PILE_PATH")
SECOND="$("$BOOTSTRAP" import)"
BYTES_AFTER=$(wc -c < "$PILE_PATH")
if [ "$FIRST" != "$SECOND" ] || [ "$BYTES_BEFORE" -ne "$BYTES_AFTER" ]; then
  echo "    FAIL: exact replay changed output or grew the pile" >&2
  exit 1
fi
echo "    OK: exact replay is idempotent"

EXPECTED_FRAGMENTS=21
EXPECTED_GOALS=7
ACTUAL_FRAGMENTS=$("$WIKI" list --tag bootstrap 2>/dev/null \
  | { grep -cE "^[0-9a-f]" || true; })
ACTUAL_GOALS=$("$COMPASS" list 2>/dev/null \
  | { grep -cE "^- \[" || true; })
if [ "$ACTUAL_FRAGMENTS" -ne "$EXPECTED_FRAGMENTS" ]; then
  echo "    FAIL: expected $EXPECTED_FRAGMENTS bootstrap entries, got $ACTUAL_FRAGMENTS" >&2
  exit 1
fi
if [ "$ACTUAL_GOALS" -ne "$EXPECTED_GOALS" ]; then
  echo "    FAIL: expected $EXPECTED_GOALS bootstrap goals, got $ACTUAL_GOALS" >&2
  exit 1
fi
echo "    OK: $ACTUAL_FRAGMENTS Wiki entries, $ACTUAL_GOALS Compass goals"

CHECK_OUT=$("$WIKI" check --compile 2>&1)
if ! grep -q "0 issues" <<<"$CHECK_OUT"; then
  echo "    FAIL: wiki check reported issues:" >&2
  echo "$CHECK_OUT" >&2
  exit 1
fi
"$WIKI" lint --check >/dev/null
echo "    OK: current Wiki frontier has valid links and Typst"

echo
echo "==> Portable bootstrap verifier passed"
echo "$FIRST"
