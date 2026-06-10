= Recipe: Auth Setup for a Multi-Agent Team

How to bootstrap capability auth so two or more agents can sync a
shared pile through a relay without exposing it to anyone else.
Chains `trible team`, `trible pile net`, and the env-var
configuration the relay reads.

== Why a recipe

Per-faculty docs cover `team create`, `team invite`, etc. in
isolation. This recipe shows the *order of operations* across
two machines (founder + invitee) so the handoff doesn't drop
mid-stream — one missing env var on the relay side and every
connection silently rejects.

== The recipe — founder bootstraps, invites one teammate

```sh
# === Founder, on machine A ===

# 1. Create the team. ARCHIVE the SECRET line offline before
#    moving past this prompt.
trible team create --pile shared.pile --key founder.key
# → team root pubkey:  d5263a4d...
# → team root SECRET:  <archive offline; never commit>
# → founder cap (sig): 4e6e02d5...
# → expires: 2026-05-28 ...

# 2. Tell the invitee to print their iroh identity:
#      ssh invitee@machine-b "trible pile net identity --key node.key"
# → node: c726b586...

# 3. Issue the invitee's cap.
trible team invite \
  --pile shared.pile \
  --team-root d5263a4d... \
  --cap 4e6e02d5... \
  --key founder.key \
  --invitee c726b586... \
  --scope read
# → issued cap (sig): f0f6f41e...

# 4. Send the (team_root, issued_cap_sig) pair to the invitee.
#    These two values are NOT secrets — the team_root is the
#    public verification anchor, the cap-sig handle is a
#    content-addressed reference. Safe to email/Signal/etc.

# === Invitee, on machine B ===

# 5. Set the env vars and verify what they'll present:
export TRIBLE_TEAM_ROOT=d5263a4d...
export TRIBLE_TEAM_CAP=f0f6f41e...
trible pile net status --key node.key
# → node:      c726b586...
# → team_root: d5263a4d...  (from TRIBLE_TEAM_ROOT)
# → self_cap:  f0f6f41e...  (from TRIBLE_TEAM_CAP)

# 6. Optional: rehearse the auth handshake locally before
#    connecting. Requires the founder to have shared the
#    cap blob too (typically via the same gossip mesh, but for
#    first connection you can copy `shared.pile` over).
trible team show --pile shared.pile --cap "$TRIBLE_TEAM_CAP" \
  --verify "$TRIBLE_TEAM_ROOT"
# → ✓ VERIFIED  ←  matches what the relay would report at OP_AUTH

# 7. Connect to the relay (founder) and sync. The gossip mesh
#    is identified by the team root pubkey (no separate topic
#    flag) — once `TRIBLE_TEAM_ROOT` is set, both peers join
#    the same mesh automatically.
trible pile net sync ./local.pile \
  --peers <founder-iroh-node-id> \
  --key node.key
```

== Why each step

  - *team create first, before anything else*: the team root
    SECRET is generated here and you can't recover it. Archive
    BEFORE proceeding.
  - *Identity exchange via plain text*: pubkeys and cap handles
    are not secrets. Don't paranoid-encrypt them; do paranoid-
    encrypt the team root SECRET.
  - *pile net status before sync*: the diagnostic confirms
    what would be presented on `OP_AUTH`. Catches "I forgot to
    `export`" before it produces "connection refused" with no
    further info.
  - *team show --verify as rehearsal*: the relay enforces auth
    at `OP_AUTH` time. `team show --verify` runs the same
    `verify_chain` locally so you see the result without
    needing to debug a network round-trip.
  - *gossip mesh = team root*: the gossip mesh is identified by
    the team root pubkey directly. One identifier per team
    handles both auth (cap chain verification) and rendezvous
    (gossip topic) — there's no way to "join the right team but
    the wrong gossip channel" because they're the same channel.

== Revoking a teammate

```sh
# Founder needs the team root SECRET (loaded from the offline
# archive, NOT from $TRIBLE_TEAM_CAP — that's the founder's
# operating cap, not the team root's secret key).
trible team revoke \
  --pile shared.pile \
  --team-root-secret <secret-hex-from-offline-archive> \
  --target <revoked-pubkey-hex>

# The revocation cascades transitively: every cap the revoked
# pubkey signed (or chained through) is invalidated. The next
# `pile net sync` snapshot refresh on each relay picks it up
# without restart.
```

== Cross-references

  - "Teams: Capability-Based Membership" — per-command
    detail and the env-var fallback semantics
  - "Recipe: Multi-Agent Coordination" — how agents
    coordinate AFTER they're synced (this recipe gets them
    synced; that one runs them through their first hand-off)
  - The `triblespace-rs/book/src/capability-auth.md` chapter
    has the complete protocol-level reference

Next stop: wiki:44d63d174814371c7468a3e604ed2303 — Getting Started: Your First Hour (tour complete).
