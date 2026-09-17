#!/bin/bash
# Recover texts stranded by descriptor-generation cutovers. NOT YET APPROVED.
#
# WHAT HAPPENED. A collection's identity is the blake3 of its descriptor blob,
# and the descriptor embeds the admission-policy encoding. So any change to that
# encoding re-mints a new collection FOR EVERY FACULTY AT ONCE, and the previous
# generation is left resident and unreachable. It happened four times between
# 2026-08-28 and 2026-09-06, three of them inside 48 hours, plus an older fifth
# generation whose `collection_name` used a retired pinned ShortString attribute
# the current reader cannot see.
#
# Nobody noticed for three weeks, because there is nothing to notice: the faculty
# resolves the new handle, finds zero records, and carries on. A schema change
# presents as a clean fresh start, not as an error.
#
# The cost: 289 texts exist in the pile that no live collection can reach, 215 of
# them substantial prose -- 48 first-person memory-journal entries, 101 compass
# goal and note texts, 38 message envelopes with 19 read-acks, and wiki fragments.
#
# THE KEY MATTERS MORE THAN ANYTHING ELSE HERE. TRIBLESPACE_KEY / self.key is the
# sky-author key 15335AAC, NOT the root. Every live collection's WRITE root is
# C5C9F620, and every commit in every dead generation is already signed by it.
# Ed25519 is deterministic, so adopting under C5C9F620 regenerates byte-identical
# commit records for rows already present and the grow-only set absorbs them --
# genuinely idempotent, 12,298 records. Adopting under the box key re-signs every
# row under a new author: 42,671 records. JP has raised a real argument for
# preferring the box key anyway (we are moving to three roots, and C5C9 should be
# a root that DELEGATES rather than a day-to-day signer); that question is open.
# Set KEY deliberately and know which you chose.
#
# --dry-run GIVES NO IDEMPOTENCE SIGNAL. It reports the SOURCE commit count, not
# net-new: `message` says "8481 to adopt" on the first run, the second run, and
# with the wrong key, identically. Net-new figures below were computed separately
# by comparing (collection, data, metadata, author) tuples. Do not read a
# dry-run's number as what it will append.
#
# Every line below carries --dry-run. Remove it only after review.

set -euo pipefail
WS=${WS:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}
PILE="$HOME"/.local/share/triblespace/custody/self.pile
KEY="$WS"/legacy-root-c5c9-20260915.key   # the C5C9F620 root -- see above

adopt() { # <label> <net-new> <from> <into>
  echo "# $1 (net new: $2)"
  trible pile collection adopt "$PILE" --key "$KEY" --from "blake3:$3" --into "blake3:$4" --dry-run
}

# Same-name generation C -> live D. 423 commits, ~108 KB, recovers 224 of 289.
adopt compass        91 70fc2f5fbb3f604652cf0f80d584d18fd857dbf84bade7a8e70f582c88921748 3583b4fdfdb04592c9a876020305ae6ff6642eec6dfa405a675baf38d1642e0c
adopt memory-journal 48 87c0094b1f274a4c1c110d7751ee883f710d7aea4649b241cd8a781b5814fa44 bc2fc4cb24bebf75bceadd1fc81fa5630b786ee637c62ec25f570d533036e46b
adopt message        56 b6d9ac1817b8f05e7424f551c6b32638596cd8b63c6c39db019071960735539c b89287c34747ba5e737294049e2df991ded0f10b5b2ccc1f468afd3feb096cc7
adopt wiki            7 ec40319c2a6b53236c3f13e9dd72e3b8eda5ee062ac200e7482dc049f9c7d552 11867c74525c9c74da62f277cb6e083eb643d2aae85aea193086f73e7c1614a6
adopt decide          2 48bbad6f692409363ea8b3065de0f73cba6bf26500a4f8a6ae2afa9fdee3f187 9f4af7d9d28cb3d65f8fc31e7ebe22e88821ca7c1c46a6b6b1eb6233f01aa56d
adopt posture-scan   15 0c333f04d0fed7a6e44fab8ffd1f54354456d0e2f6131b5944f28c388e16b413 e6ff000c0d26a122733c93ff587fbabc09b6cc89bb0b2efeb672cd49fb06007f

# DELIBERATELY EXCLUDED, each for its own reason:
#
# orient (204 commits, 42 items). Machine state, not prose: {"version":3,
# "unread":[...]} snapshots. Recovery value zero; restoring stale ones could
# resurface three-week-old messages as unread and wake watchers. The only item on
# the list where the asymmetry runs against recovering.
#
# retired `memory` -> memory-journal, and two anchorless siblings (11,875 commits
# for 54 texts). The split into memory-journal/memory-comb re-minted entity ids,
# so 3,368 of that collection's 3,390 texts are ALREADY live under different ids.
# Bulk-adopting recovers 54 and plants ~3,400 duplicate journal entries. Extract
# those 54 and re-file them deliberately instead.
#
# secrets, two vault-*, three unnamed anchorless (~13 texts). No live counterpart
# to adopt INTO: every secrets-access collection carries a pre-GEN-D undecodable
# policy, and `secrets` is the one faculty with no pin in
# $HOME/.config/triblespace/faculty-collections.env, so its current-generation
# collection has never been written. Creating a target is a decision about the
# secrets faculty, not a recovery step.
#
# AND THE PART THAT MATTERS AFTER THE RECOVERY: none of this stops it happening
# again. The next policy-schema change -- for instance moving from one root key to
# three, which is planned -- re-mints every collection exactly the same way, and
# would strand everything CURRENT rather than three-week-old leftovers. Recovery
# is the past; the fix is making a re-mint loud (a collection resolving to zero
# records while same-named siblings hold thousands should exit non-zero) or making
# it impossible (take the policy encoding out of the identity core).
