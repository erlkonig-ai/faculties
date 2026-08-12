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

# Make the issued capability blob and its ancestor closure available to the
# invitee. A running issuer daemon pushes them to the invitee daemon through
# `OP_DELIVER_CAP`; for an offline handoff, transfer and import a pile snapshot
# that contains that closure. The printed handle alone is not the capability.

# Invitee connects to the current legacy-head/blob sync transport with the
# now-local issued cap as their credential. Native collection-record transport
# is a separate integration boundary and is not claimed by this command yet.
TRIBLE_TEAM_ROOT=<pubkey> TRIBLE_TEAM_CAP=<issued-sig> \
trible pile net sync ./self.pile \
  --peers <founder-node-id>

# Audit at any time:
trible team list --pile shared.pile
# Lists each stored cap (issuer → subject, scope, expiry) sorted by
# soonest-to-expire first.
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

== Ending renewal

Capabilities are short-lived. Issuing or approving one also creates a local
renewal-policy entry; ending that policy lets the peer's capability chain
expire naturally. There is no misleading global revoke assertion that
promises to erase a capability another node has already observed.

```sh
trible team list-issued --pile shared.pile
trible team retract --pile shared.pile --entry <renewal-entry-id>
```

The running daemon observes that local decision on its next tick and stops
renewing the selected `(subject, scope)` grant. Existing signed caps remain
valid only until their bounded expiry. Treat loss of an active signing key as a
credential incident during that remaining window.

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

Next stop: [Relations: People and Handle Mappings](wiki:e7e3f672a66b39e0b5b3c0eaf212b1da).
