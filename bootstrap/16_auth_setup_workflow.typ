= Recipe: Auth Setup for a Multi-Agent Team

This recipe bootstraps one team's positive CONNECT authority across two
machines. The founder publishes a root grant, issues one exact child grant,
and exports a portable proof bundle. The invitee verifies and imports that
bundle before native collection synchronization begins. No ambient policy
database, environment variables, or pre-auth proof fetch is involved.

== The recipe — founder bootstraps, invites one teammate

```sh
# === Founder, on machine A ===

# 1. Create the pile and team. Archive the printed root secret offline.
trible pile create founder.pile
trible team create --pile founder.pile --key founder.key
# → team root pubkey: <team-root>
# → team root SECRET: <archive offline; never commit>
# → founder grant:    <founder-grant>
trible pile net identity --key founder.key
# → node: <founder-node-id>

# 2. Invitee creates its local pile and transport key, then sends only the
#    public identity to the founder.
trible pile create invitee.pile
trible pile net identity --key invitee.key
# → node: <invitee-public-key>

# 3. Founder issues a CONNECT child and writes its complete public proof.
trible team invite \
  --pile founder.pile \
  --team-root <team-root> \
  --parent <founder-grant> \
  --key founder.key \
  --invitee <invitee-public-key> \
  --out invitee.invite
# → issued grant:  <invitee-grant>
# → invite bundle: invitee.invite

# 4. Transfer invitee.invite through any ordinary file channel.

# === Invitee, on machine B ===

# 5. Verify the proof against the local key and import its descriptor, grant
#    archives, and signed COMMITs. Repeating this command is harmless.
trible team join \
  --pile invitee.pile \
  --key invitee.key \
  --invite invitee.invite
# → team root:      <team-root>
# → accepted grant: <invitee-grant>

# 6. Rehearse the exact claim the transport will authenticate.
trible pile net status invitee.pile \
  --key invitee.key \
  --team-root <team-root> \
  --grant <invitee-grant>

# 7. Connect and exchange native collection evidence. Referenced content stays
#    lazy; durable WANTs drive blob, merge-receipt, and derive-receipt fetching.
trible pile net sync invitee.pile \
  --peers <founder-node-id> \
  --key invitee.key \
  --team-root <team-root> \
  --grant <invitee-grant>
```

The founder must start `pile net sync founder.pile` with the founder key, team
root, and founder grant; no `--peers` argument is needed when the invitee is
dialing it. Add `--delegate` while issuing the invite only if the invitee should
be able to issue further child CONNECT grants. Sync runs until interrupted
unless `--duration` or `--quiescent-for` sets a bounded stopping policy.

== Why each step

  - *Archive the team-root secret*: it is shown once and deliberately not
    persisted. Anyone holding it can publish an independent root grant.
  - *Exchange the invitee's public key*: public keys and invite bundles are not
    secrets. The invite remains usable only by the private key named at its
    leaf.
  - *Transfer one bundle*: it contains the complete bounded root-to-leaf proof,
    so first contact does not need a pre-auth network exception or an ambient
    proof store.
  - *Join before status*: `join` verifies the claim and imports the same
    immutable evidence that `status` and `sync` later resolve locally.
  - *Pass root and grant explicitly*: the transport never guesses a team or
    credential from environment variables or mutable process state.
  - *Keep gossip distinct from authority*: the team root identifies the gossip
    topic, while collection descriptors decide what may be relayed and each
    collection resolver decides which authors have semantic `WRITE` authority.
    A CONNECT proof grants neither.

== Removing access

There is no renewal or retraction command. Positive grants are grow-only, so
ending durable access requires a successor team, collection, or key epoch and
an admission boundary that stops serving the old epoch. Simply issuing a new
grant under the old team does not invalidate an already accepted proof.

== Cross-references

  - [Teams: Positive Authority and CONNECT](wiki:67477d2173928fd91ef20173eabfeae4)
    — the command surface and authority semantics
  - [Recipe: Multi-Agent Coordination](wiki:45e1b9bef3ad9836536ab7bce367deb0)
    — agent hand-offs once the substrate is connected
  - `triblespace-rs/book/src/capability-auth.md` — complete authority and proof
    reference
  - `triblespace-rs/book/src/distributed-sync.md` — sparse gossip, direct RPC,
    and durable WANT reconciliation

Next stop: [Getting Started: Your First Hour (tour complete)](wiki:44d63d174814371c7468a3e604ed2303).
