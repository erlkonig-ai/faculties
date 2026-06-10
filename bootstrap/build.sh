#!/usr/bin/env bash
#
# Regenerate ../bootstrap.pile from the .typ sources in this directory.
# Use this when fragment content drifts; new agents getting onboarded
# pick up the refreshed substrate via `cat bootstrap.pile >> self.pile`.
#
# Usage:
#   cd faculties/bootstrap && ./build.sh
#
set -euo pipefail

BOOTSTRAP_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$BOOTSTRAP_DIR/.."
PILE_PATH="$BOOTSTRAP_DIR/../bootstrap.pile"

# Build the faculty binaries on demand so the bootstrap pile rebuilds
# from a fresh checkout without requiring a separate `cargo install`
# step. Path the release artefacts directly so the rest of the script
# can quote them like any other binary.
echo "==> Pre-building bins"
cargo build --quiet --manifest-path="$REPO_ROOT/Cargo.toml" --release --bin wiki --bin compass
WIKI="$REPO_ROOT/target/release/wiki"
COMPASS="$REPO_ROOT/target/release/compass"

# Start fresh — old fragments from previous builds would orphan
# but never disappear (piles are append-only). Regenerating into
# a clean file is simpler than de-duping.
rm -f "$PILE_PATH"
touch "$PILE_PATH"
export PILE="$PILE_PATH"

echo "==> Building wiki fragments"

# Each fragment: (title, source-file, tags...). Tags repeat
# `bootstrap onboarding` plus a topic-specific tag.

# 1. How faculties work
"$WIKI" create "How Faculties Work" \
  "@$BOOTSTRAP_DIR/01_how_faculties_work.typ" \
  --tag bootstrap --tag onboarding --tag faculties >/dev/null

# 2. Wiki style guide
"$WIKI" create "Wiki Fragment Style Guide" \
  "@$BOOTSTRAP_DIR/02_wiki_style_guide.typ" \
  --tag bootstrap --tag onboarding --tag wiki >/dev/null

# 3. Compass workflow
"$WIKI" create "Compass Goals Workflow" \
  "@$BOOTSTRAP_DIR/03_compass_workflow.typ" \
  --tag bootstrap --tag onboarding --tag compass >/dev/null

# 4. When to use codex
"$WIKI" create "When to Use Codex (and When Not To)" \
  "@$BOOTSTRAP_DIR/04_when_to_use_codex.typ" \
  --tag bootstrap --tag onboarding --tag codex --tag subagents >/dev/null

# 5. Work as its own ledger
"$WIKI" create "Work As Its Own Ledger" \
  "@$BOOTSTRAP_DIR/05_work_as_its_own_ledger.typ" \
  --tag bootstrap --tag onboarding --tag design --tag principle >/dev/null

# 6. Tool selection
"$WIKI" create "Tool Selection: Faculties First" \
  "@$BOOTSTRAP_DIR/06_tool_selection.typ" \
  --tag bootstrap --tag onboarding --tag tools --tag reference >/dev/null

# 7. Getting started — references siblings by title, not by
# fragment id, so `wiki.rs list --tag bootstrap` is the
# navigation surface. Avoids hardcoded ids that would drift on
# every rebuild (the wiki faculty mints fresh fragment ids per
# build).
"$WIKI" create "Getting Started: Your First Hour" \
  "@$BOOTSTRAP_DIR/07_getting_started.typ" \
  --tag bootstrap --tag onboarding --tag start-here >/dev/null

# 8. Files faculty — usage patterns for `files.rs add/fetch/list`,
# why content-addressing matters, citation conventions for wiki
# fragments.
"$WIKI" create "Files Faculty: Archiving and Citing Artefacts" \
  "@$BOOTSTRAP_DIR/08_files_faculty.typ" \
  --tag bootstrap --tag onboarding --tag files >/dev/null

# 9. Teams — `trible team` lifecycle, env-var-driven config,
# `pile net status` diagnostic, when to revoke. The auth-arc
# tool surface, which is its own user-facing chapter in the
# triblespace-rs book.
"$WIKI" create "Teams: Capability-Based Membership" \
  "@$BOOTSTRAP_DIR/09_teams_faculty.typ" \
  --tag bootstrap --tag onboarding --tag teams --tag auth >/dev/null

# 10. Local messages — direct agent-to-agent DM with read
# acknowledgements. Tool Selection table flags this as the
# right choice for transient, addressee-specific notes.
"$WIKI" create "Local Messages: Agent-to-Agent Direct Messaging" \
  "@$BOOTSTRAP_DIR/10_local_messages_faculty.typ" \
  --tag bootstrap --tag onboarding --tag local-messages --tag coordination >/dev/null

# 11. Orient — situation snapshot of recent messages + doing +
# todo. The "where was I?" command. Includes `orient.rs wait`
# for blocking on relevant branch changes (idle-agent
# coordination primitive).
"$WIKI" create "Orient: The Situation-Snapshot Faculty" \
  "@$BOOTSTRAP_DIR/11_orient_faculty.typ" \
  --tag bootstrap --tag onboarding --tag orient --tag coordination >/dev/null

# 12. Relations — contacts/handle registry. The label-to-person
# mapping that local_messages and compass workflows resolve
# recipient/assignee references through. Conventions for
# labels, aliases, when not to use it (network identities
# belong to team CLI state, not relations).
"$WIKI" create "Relations: People and Handle Mappings" \
  "@$BOOTSTRAP_DIR/12_relations_faculty.typ" \
  --tag bootstrap --tag onboarding --tag relations --tag people >/dev/null

# 13. Web — search/fetch via Tavily/Exa providers. Pairs with
# files.rs (search → pick URL → files.rs fetch to archive raw
# bytes → wiki fragment citing the file hash). Recorded on
# the pile's web branch as queryable events.
"$WIKI" create "Web: Search and Fetch Through Provider APIs" \
  "@$BOOTSTRAP_DIR/13_web_faculty.typ" \
  --tag bootstrap --tag onboarding --tag web --tag research >/dev/null

# 14. Research workflow recipe — chains compass → web → files
# → wiki for the most common agent task. The recipe layer
# above per-faculty docs: shows how the composable faculty
# model actually composes in practice.
"$WIKI" create "Recipe: Research Workflow" \
  "@$BOOTSTRAP_DIR/14_research_workflow.typ" \
  --tag bootstrap --tag onboarding --tag recipe --tag research >/dev/null

# 15. Multi-agent coordination recipe — chains relations,
# local_messages, orient, compass for two-agent handoff
# patterns. The non-obvious bit is the handshake order:
# status change is durable signal, message is the
# notification, notes are the audit trail.
"$WIKI" create "Recipe: Multi-Agent Coordination" \
  "@$BOOTSTRAP_DIR/15_coordination_workflow.typ" \
  --tag bootstrap --tag onboarding --tag recipe --tag coordination >/dev/null

# 16. Auth setup recipe — chains `trible team`, `trible pile
# net`, and the env-var configuration relays read. Order of
# operations across founder + invitee machines so the
# capability handoff doesn't silently drop on a missing export.
"$WIKI" create "Recipe: Auth Setup for a Multi-Agent Team" \
  "@$BOOTSTRAP_DIR/16_auth_setup_workflow.typ" \
  --tag bootstrap --tag onboarding --tag recipe --tag auth >/dev/null

# 17-19. Substrate concepts — the in-depth "why does this
# work" layer behind the workflow fragments. Read on demand,
# not required for day-one productivity. Also double as
# presentation material: one concept per fragment, one
# diagram each (trible → pile → merge).
"$WIKI" create "Substrate 1/3: What Is a Trible" \
  "@$BOOTSTRAP_DIR/17_substrate_tribles.typ" \
  --tag bootstrap --tag onboarding --tag substrate --tag concepts >/dev/null

"$WIKI" create "Substrate 2/3: The Pile" \
  "@$BOOTSTRAP_DIR/18_substrate_pile.typ" \
  --tag bootstrap --tag onboarding --tag substrate --tag concepts >/dev/null

"$WIKI" create "Substrate 3/3: Monotonic Merge" \
  "@$BOOTSTRAP_DIR/19_substrate_merge.typ" \
  --tag bootstrap --tag onboarding --tag substrate --tag concepts >/dev/null

echo "    19 fragments created"

echo "==> Building compass goals"

"$COMPASS" add "Read the start-here wiki fragment" \
  --tag bootstrap --tag onboarding \
  --note "Run \`wiki.rs list --tag bootstrap\` to find the 'Getting Started: Your First Hour' fragment, then \`wiki.rs show <id>\` to read it. This is your orientation tour." >/dev/null

"$COMPASS" add "Mint your first id with \`trible genid\`" \
  --tag bootstrap --tag faculties \
  --note "Stable IDs in TribleSpace are minted, never guessed. Run \`trible genid\` and copy the 32-char hex output. Try minting 3 in a row — they should all be different." >/dev/null

"$COMPASS" add "Create your first wiki fragment" \
  --tag bootstrap --tag wiki \
  --note "Pick something you've learned today. Write a 5-10 line typst body to /tmp/myfrag.typ, then \`wiki.rs create \"My first fragment\" @/tmp/myfrag.typ --tag personal\`. Verify with \`wiki.rs show <id>\`." >/dev/null

"$COMPASS" add "Archive a file with \`files.rs add\`" \
  --tag bootstrap --tag files \
  --note "Pick any local file (not a binary in a git repo). Run \`files.rs add <path>\`. The output \`files:<hash>\` is a content-addressed reference you can cite from wiki fragments. Confirm the hash is stable: re-run on the same file, same hash." >/dev/null

"$COMPASS" add "Run \`wiki.rs lint\` and \`wiki.rs check\`" \
  --tag bootstrap --tag wiki --tag hygiene \
  --note "lint applies markdown→typst transforms and rebuilds the links_to index. check reports orphan fragments, broken links, truncated ids. Run both. Note any warnings — they're the wiki's self-diagnostic surface." >/dev/null

"$COMPASS" add "Mark this goal done and write an outcome note" \
  --tag bootstrap --tag compass \
  --note "When you finish working through the bootstrap goals, move this one to done with \`compass.rs move <id> done\` and add a final note recording what stuck and what you'd improve. The outcome note IS the audit trail." >/dev/null

echo "    6 goals created"

# ── Sanity check ──────────────────────────────────────────────────
# Verify the build actually produced the expected content. This
# catches silent breakage where a fragment fails to compile (typst
# error) or the wiki/compass faculty changes shape — the script
# would otherwise exit 0 with a partial pile.
echo
echo "==> Sanity check"
# Bump these when adding/removing entries above.
EXPECTED_FRAGMENTS=19
EXPECTED_GOALS=6
ACTUAL_FRAGMENTS=$("$WIKI" list --tag bootstrap 2>/dev/null \
  | grep -cE "^[0-9a-f]" || echo 0)
ACTUAL_GOALS=$("$COMPASS" list 2>/dev/null \
  | grep -cE "^- \[" || echo 0)
if [ "$ACTUAL_FRAGMENTS" -ne "$EXPECTED_FRAGMENTS" ]; then
  echo "    FAIL: expected $EXPECTED_FRAGMENTS bootstrap fragments, got $ACTUAL_FRAGMENTS" >&2
  exit 1
fi
if [ "$ACTUAL_GOALS" -ne "$EXPECTED_GOALS" ]; then
  echo "    FAIL: expected $EXPECTED_GOALS bootstrap goals, got $ACTUAL_GOALS" >&2
  exit 1
fi
echo "    OK: $ACTUAL_FRAGMENTS fragments, $ACTUAL_GOALS goals"

echo
echo "==> Done. bootstrap.pile is at $PILE_PATH"
echo "    $(ls -lh "$PILE_PATH" | awk '{print $5}') / $(wc -c < "$PILE_PATH") bytes"
