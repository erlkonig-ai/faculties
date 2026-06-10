= Teams: Capability-Based Membership

For multi-agent setups where each agent runs its own pile and
syncs through a relay, capabilities are how the relay decides
who's allowed to read or write. The team CLI lives at
`trible team` (not as a `.rs` faculty — it ships with the
trible CLI itself, since auth setup is pile-specific).

== Quick lifecycle

```sh
# Founder, on machine A:
trible team create --pile shared.pile --key founder.key
# Prints: team root pubkey, team root SECRET (archive offline),
#         founder cap (sig) handle, expiry timestamp.

# Invitee, on machine B:
trible pile net identity --key invitee.key
# Prints: node: <invitee-pubkey>

# Founder issues invitee's cap:
trible team invite --pile shared.pile \
  --team-root <pubkey> --cap <founder-sig> \
  --key founder.key \
  --invitee <invitee-pubkey> --scope read

# Invitee runs the relay, with the issued cap as their credential:
TRIBLE_TEAM_ROOT=<pubkey> TRIBLE_TEAM_CAP=<issued-sig> \
trible pile net sync ./self.pile \
  --peers <founder-node-id> --topic team-graph

# Audit at any time:
trible team list --pile shared.pile
# Lists each cap (issuer → subject, scope, expiry) sorted by
# soonest-to-expire first, plus revocations.
```

== Diagnostics

`trible pile net status --key <key>` prints what auth values
the running peer would present on `OP_AUTH`:

  - `node`: the iroh identity (your peer id)
  - `team_root`: from `TRIBLE_TEAM_ROOT` env var, or single-user
    fallback to your own pubkey
  - `self_cap`: from `TRIBLE_TEAM_CAP` env var, or all-zeros
    sentinel (which the relay rejects — that's the right signal
    that you need to set the env var)

Use this when a connection is being rejected and you want to
double-check what your side is presenting before debugging the
relay.

== When to revoke

  - Lost credentials (laptop with `invitee.key` stolen).
  - Member leaves the team.
  - Compromised cap (e.g. you accidentally pasted
    `TRIBLE_TEAM_CAP` into a public channel).

```sh
trible team revoke --pile shared.pile \
  --team-root-secret <hex> \
  --target <pubkey-of-revoked-member>
```

Revocations cascade transitively: revoking a member's pubkey
also invalidates every cap that member issued downstream.
The relay picks up new revocations on the next snapshot
refresh — no restart.

== When NOT to use this

  - Solo workflows — you're already a team-of-one. The single-user
    fallback (`team_root = signing_key.verifying_key()`) means
    nothing else needs to be set up.
  - Read-only public mirrors — those don't need cap auth, they
    just need anyone-can-read. Currently the protocol assumes
    auth on every connection; "public mode" is its own design.

== Reference

  - User chapter: `triblespace-rs/book/src/capability-auth.md`
  - Library: `triblespace_core::repo::capability` (with
    runnable doctests on every primary public fn)
  - Protocol: `triblespace_net::host::serve_stream`

Next stop: wiki:e7e3f672a66b39e0b5b3c0eaf212b1da — Relations: People and Handle Mappings.
