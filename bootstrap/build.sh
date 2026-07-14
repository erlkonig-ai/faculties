#!/usr/bin/env bash
#
# Regenerate ../bootstrap.pile from the .typ sources in this directory.
# Use this when fragment content drifts. New agents start from it
# (`cp bootstrap.pile self.pile`); existing piles merge it in
# (`cat bootstrap.pile >> self.pile`).
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

# Stable fragment ids — minted once with `trible genid`, never regenerated.
# The .typ sources cross-link via wiki:<id> using these exact values, so
# rebuilds keep the tour spine and any external references valid.
ID_HOWFAC=25e8f009e33207755109f19f7a68dff5
ID_STYLE=82129c70b693f7e2d781d78ac5efbb86
ID_COMPASS=7cdd48c272ff344628fe74f4c07783e4
ID_LEDGER=996e648886cccb61d1afd48296b0a0cb
ID_TOOLSEL=f4aff48fff04f313552f5b32244f9873
ID_START=44d63d174814371c7468a3e604ed2303
ID_FILES=b08448855de9cce7610d68dac2555003
ID_TEAMS=67477d2173928fd91ef20173eabfeae4
ID_LMSG=65c6965cb3d11052e87804527734a697
ID_ORIENT=ff27b500d93e1d545b7465438a0146e1
ID_RELATIONS=e7e3f672a66b39e0b5b3c0eaf212b1da
ID_WEB=abe651f605c823085d861f296d9f9907
ID_RESEARCH=999d2565f2e3af57fa5cfe2ed507d450
ID_COORD=45e1b9bef3ad9836536ab7bce367deb0
ID_HOOKS=5c86df3dcd5994de2967483fca7170ac
ID_AUTH=d06247b9d9183721e47a2940806e5d7f
ID_TRIBLE=4e19893b36bf37d471bb9ea968edac20
ID_PILEF=5232ea531fedfcb17bf15e88c3d52a36
ID_MERGE=5cc10e2b0263008b261cf8a1ef30bd8c
ID_ARCH=6e5f38bdfd589cd0359bf668d1af9841
ID_AUTHORING=864c45bed65311b27b1cafe268b6ed2d

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
"$WIKI" create "How Faculties Work" --force --id "${ID_HOWFAC}" \
  "@$BOOTSTRAP_DIR/01_how_faculties_work.typ" \
  --tag bootstrap --tag onboarding --tag faculties >/dev/null

# 2. Wiki style guide
"$WIKI" create "Wiki Fragment Style Guide" --force --id "${ID_STYLE}" \
  "@$BOOTSTRAP_DIR/02_wiki_style_guide.typ" \
  --tag bootstrap --tag onboarding --tag wiki >/dev/null

# 3. Compass workflow
"$WIKI" create "Compass Goals Workflow" --force --id "${ID_COMPASS}" \
  "@$BOOTSTRAP_DIR/03_compass_workflow.typ" \
  --tag bootstrap --tag onboarding --tag compass >/dev/null

# 5. Work as its own ledger
"$WIKI" create "Work As Its Own Ledger" --force --id "${ID_LEDGER}" \
  "@$BOOTSTRAP_DIR/05_work_as_its_own_ledger.typ" \
  --tag bootstrap --tag onboarding --tag design --tag principle >/dev/null

# 6. Tool selection
"$WIKI" create "Tool Selection: Faculties First" --force --id "${ID_TOOLSEL}" \
  "@$BOOTSTRAP_DIR/06_tool_selection.typ" \
  --tag bootstrap --tag onboarding --tag tools --tag reference >/dev/null

# 7. Getting started — references siblings by title, not by
# fragment id, so `wiki list --tag bootstrap` is the
# navigation surface. Avoids hardcoded ids that would drift on
# every rebuild (the wiki faculty mints fresh fragment ids per
# build).
"$WIKI" create "Getting Started: Your First Hour" --force --id "${ID_START}" \
  "@$BOOTSTRAP_DIR/07_getting_started.typ" \
  --tag bootstrap --tag onboarding --tag start-here >/dev/null

# 8. Files faculty — usage patterns for `files add/fetch/list`,
# why content-addressing matters, citation conventions for wiki
# fragments.
"$WIKI" create "Files Faculty: Archiving and Citing Artefacts" --force --id "${ID_FILES}" \
  "@$BOOTSTRAP_DIR/08_files_faculty.typ" \
  --tag bootstrap --tag onboarding --tag files >/dev/null

# 9. Teams — `trible team` lifecycle, env-var-driven config,
# `pile net status` diagnostic, when to revoke. The auth-arc
# tool surface, which is its own user-facing chapter in the
# triblespace-rs book.
"$WIKI" create "Teams: Capability-Based Membership" --force --id "${ID_TEAMS}" \
  "@$BOOTSTRAP_DIR/09_teams_faculty.typ" \
  --tag bootstrap --tag onboarding --tag teams --tag auth >/dev/null

# 10. Local messages — direct agent-to-agent DM with read
# acknowledgements. Tool Selection table flags this as the
# right choice for transient, addressee-specific notes.
"$WIKI" create "Local Messages: Agent-to-Agent Direct Messaging" --force --id "${ID_LMSG}" \
  "@$BOOTSTRAP_DIR/10_local_messages_faculty.typ" \
  --tag bootstrap --tag onboarding --tag local-messages --tag coordination >/dev/null

# 11. Orient — situation snapshot of recent messages, doing/todo,
# and exact review obligations. Includes persona-scoped wait/poll;
# review requests summon their frozen reviewers without a second
# notification record.
"$WIKI" create "Orient: The Situation-Snapshot Faculty" --force --id "${ID_ORIENT}" \
  "@$BOOTSTRAP_DIR/11_orient_faculty.typ" \
  --tag bootstrap --tag onboarding --tag orient --tag coordination >/dev/null

# 12. Relations — contacts/handle registry. The label-to-person
# mapping that message and compass workflows resolve
# recipient/assignee references through. Conventions for
# labels, aliases, when not to use it (network identities
# belong to team CLI state, not relations).
"$WIKI" create "Relations: People and Handle Mappings" --force --id "${ID_RELATIONS}" \
  "@$BOOTSTRAP_DIR/12_relations_faculty.typ" \
  --tag bootstrap --tag onboarding --tag relations --tag people >/dev/null

# 13. Web — search/fetch via Tavily/Exa providers. Pairs with
# files (search → pick URL → files fetch to archive raw
# bytes → wiki fragment citing the file hash). Recorded on
# the pile's web branch as queryable events.
"$WIKI" create "Web: Search and Fetch Through Provider APIs" --force --id "${ID_WEB}" \
  "@$BOOTSTRAP_DIR/13_web_faculty.typ" \
  --tag bootstrap --tag onboarding --tag web --tag research >/dev/null

# 14. Research workflow recipe — chains compass → web → files
# → wiki for the most common agent task. The recipe layer
# above per-faculty docs: shows how the composable faculty
# model actually composes in practice.
"$WIKI" create "Recipe: Research Workflow" --force --id "${ID_RESEARCH}" \
  "@$BOOTSTRAP_DIR/14_research_workflow.typ" \
  --tag bootstrap --tag onboarding --tag recipe --tag research >/dev/null

# 15. Multi-agent coordination recipe — conversational handoffs use
# messages; exact review assignment is derived automatically from
# Compass request heads. Covers pair/council settlement, revision refresh,
# visible forks, and reasoned break-glass evidence.
"$WIKI" create "Recipe: Multi-Agent Coordination" --force --id "${ID_COORD}" \
  "@$BOOTSTRAP_DIR/15_coordination_workflow.typ" \
  --tag bootstrap --tag onboarding --tag recipe --tag coordination >/dev/null

# 22. Harness hooks — the mechanical colony-sync layer:
# watcher (orient wait), per-turn poll (orient poll), and
# Stop-hook enforcement, with per-harness install sections
# (Claude Code / Codex / Antigravity). Models have no internal
# clock, so this is hook-enforced, not remembered; part of
# every new zooid's onboarding. Slotted after the coordination
# recipe it keeps alive.
"$WIKI" create "Harness Hooks: Mechanical Colony Sync (Watcher, Poll, Enforcement)" --force --id "${ID_HOOKS}" \
  "@$BOOTSTRAP_DIR/22_harness_hooks.typ" \
  --tag bootstrap --tag onboarding --tag hooks --tag coordination >/dev/null

# 16. Auth setup recipe — chains `trible team`, `trible pile
# net`, and the env-var configuration relays read. Order of
# operations across founder + invitee machines so the
# capability handoff doesn't silently drop on a missing export.
"$WIKI" create "Recipe: Auth Setup for a Multi-Agent Team" --force --id "${ID_AUTH}" \
  "@$BOOTSTRAP_DIR/16_auth_setup_workflow.typ" \
  --tag bootstrap --tag onboarding --tag recipe --tag auth >/dev/null

# 17-19. Substrate concepts — the in-depth "why does this
# work" layer behind the workflow fragments. Read on demand,
# not required for day-one productivity. Also double as
# presentation material: one concept per fragment, one
# diagram each (trible → pile → merge).
"$WIKI" create "Substrate 1/4: What Is a Trible" --force --id "${ID_TRIBLE}" \
  "@$BOOTSTRAP_DIR/17_substrate_tribles.typ" \
  --tag bootstrap --tag onboarding --tag substrate --tag concepts >/dev/null

"$WIKI" create "Substrate 2/4: The Pile" --force --id "${ID_PILEF}" \
  "@$BOOTSTRAP_DIR/18_substrate_pile.typ" \
  --tag bootstrap --tag onboarding --tag substrate --tag concepts >/dev/null

"$WIKI" create "Substrate 3/4: Monotonic Merge" --force --id "${ID_MERGE}" \
  "@$BOOTSTRAP_DIR/19_substrate_merge.typ" \
  --tag bootstrap --tag onboarding --tag substrate --tag concepts >/dev/null

# 20. Substrate architecture — the vertical story: agents →
# faculties → workspace → substrate. Why no faculty contains
# sync code; typst layer diagram. Caps the substrate arc.
"$WIKI" create "Substrate 4/4: The Architecture — Zero Sync Code" --force --id "${ID_ARCH}" \
  "@$BOOTSTRAP_DIR/20_substrate_architecture.typ" \
  --tag bootstrap --tag onboarding --tag substrate --tag concepts --tag architecture >/dev/null

# 21. Authoring a faculty — the one gap the tour otherwise
# leaves: it teaches how to USE faculties but not how to ADD
# one. The natural continuation of "How Faculties Work": mint
# schema ids, write src/bin/<verb>.rs, own a branch, install,
# land upstream. Slotted as How Faculties Work's Next stop.
"$WIKI" create "Authoring a Faculty" --force --id "${ID_AUTHORING}" \
  "@$BOOTSTRAP_DIR/21_authoring_a_faculty.typ" \
  --tag bootstrap --tag onboarding --tag faculties --tag authoring >/dev/null

echo "    21 fragments created"

echo "==> Building compass goals"

"$COMPASS" add "Read the start-here wiki fragment" \
  --tag bootstrap --tag onboarding \
  --note "Run \`wiki list --tag bootstrap\` to find the 'Getting Started: Your First Hour' fragment, then \`wiki show <id>\` to read it. This is your orientation tour." >/dev/null

"$COMPASS" add "Mint your first id with \`trible genid\`" \
  --tag bootstrap --tag faculties \
  --note "Stable IDs in TribleSpace are minted, never guessed. Run \`trible genid\` and copy the 32-char hex output. Try minting 3 in a row — they should all be different." >/dev/null

"$COMPASS" add "Create your first wiki fragment" \
  --tag bootstrap --tag wiki \
  --note "Pick something you've learned today. Write a 5-10 line typst body to /tmp/myfrag.typ, then \`wiki create \"My first fragment\" @/tmp/myfrag.typ --tag personal\`. Verify with \`wiki show <id>\`." >/dev/null

"$COMPASS" add "Archive a file with \`files add\`" \
  --tag bootstrap --tag files \
  --note "Pick any local file (not a binary in a git repo). Run \`files add <path>\`. The output \`files:<hash>\` is a content-addressed reference you can cite from wiki fragments. Confirm the hash is stable: re-run on the same file, same hash." >/dev/null

"$COMPASS" add "Run \`wiki lint\` and \`wiki check\`" \
  --tag bootstrap --tag wiki --tag hygiene \
  --note "lint applies markdown→typst transforms and rebuilds the links_to index. check reports orphan fragments, broken links, truncated ids. Run both. Note any warnings — they're the wiki's self-diagnostic surface." >/dev/null

"$COMPASS" add "Scaffold a trivial faculty" \
  --tag bootstrap --tag faculties --tag authoring \
  --note "Mint an id with \`trible genid\`, add \`faculties/src/bin/echofact.rs\`: a clap Cli with \`#[arg(long, env = \"PILE\")] pile\`, that opens the pile and prints one fact (e.g. the id you minted). \`cargo install --path faculties --bins\`, then run \`echofact\`. You've added a verb. See the 'Authoring a Faculty' fragment for the full skeleton." >/dev/null

"$COMPASS" add "Mark this goal done and write an outcome note" \
  --tag bootstrap --tag compass \
  --note "When you finish working through the bootstrap goals, move this one to done with \`compass move <id> done\` and add a final note recording what stuck and what you'd improve. The outcome note IS the audit trail." >/dev/null

echo "    7 goals created"

# ── Sanity check ──────────────────────────────────────────────────
# Verify the build actually produced the expected content. This
# catches silent breakage where a fragment fails to compile (typst
# error) or the wiki/compass faculty changes shape — the script
# would otherwise exit 0 with a partial pile.
echo
# Forward references (the tour graph is cyclic) get no links_to edge at
# create time — the target doesn't exist yet to classify. One lint --fix
# pass rebuilds the link index now that every fragment exists.
echo "==> Rebuilding link index"
"$WIKI" lint --fix >/dev/null 2>&1 || true
"$WIKI" lint --check >/dev/null 2>&1 || { echo "    FAIL: lint not clean after relink" >&2; exit 1; }
echo "    OK: lint clean"

echo "==> Sanity check"
# Bump these when adding/removing entries above.
EXPECTED_FRAGMENTS=21
EXPECTED_GOALS=7
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

CHECK_OUT=$("$WIKI" check 2>&1)
if ! echo "$CHECK_OUT" | grep -q "0 issues"; then
  echo "    FAIL: wiki check reported issues:" >&2
  echo "$CHECK_OUT" >&2
  exit 1
fi
echo "    OK: wiki check clean (no orphans, no dangling links)"

echo
echo "==> Done. bootstrap.pile is at $PILE_PATH"
echo "    $(ls -lh "$PILE_PATH" | awk '{print $5}') / $(wc -c < "$PILE_PATH") bytes"
