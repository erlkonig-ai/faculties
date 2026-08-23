= Teams: Positive Authority and CONNECT

For multi-agent setups where each agent runs its own pile, one public,
grow-only authority collection records who may connect and who may contribute
to exact collections. Every grant is an ordinary signed `CollectionCommit`:
the signer is the issuer, the subject is one public key, and the grant names
one exact action and resource. The team CLI lives at `trible team` because the
authority model is part of TribleSpace rather than one faculty.

`CONNECT`, collection `WRITE`, and a Secrets vault's `READ` are independent
actions interpreted by their consumers. None implies another. Gossip reach is
also separate: it is an immutable property of a collection descriptor, not a
team permission.

== Quick lifecycle

```sh
# Founder, on machine A:
trible pile create founder.pile
trible team create --pile founder.pile --key founder.key
# Prints: team root pubkey, team root SECRET, founder grant.
# Store the root secret offline; it is not written to the pile or key file.
trible pile net identity --key founder.key
# Prints: node: <founder-node-id>

# Invitee, on machine B, creates or loads its transport key:
trible pile create invitee.pile
trible pile net identity --key invitee.key
# Prints: node: <invitee-public-key>

# Founder issues a child CONNECT grant and packages its complete proof:
trible team invite --pile founder.pile \
  --team-root <team-root> --parent <founder-grant> \
  --key founder.key --invitee <invitee-public-key> \
  --out invitee.invite

# Transfer invitee.invite through any ordinary file channel. The invitee
# verifies the exact claim and idempotently imports the proof evidence:
trible team join --pile invitee.pile \
  --key invitee.key --invite invitee.invite

# Inspect the exact grant before connecting:
trible pile net status invitee.pile \
  --key invitee.key --team-root <team-root> --grant <invitee-grant>

# Audit accepted grants and inert candidate diagnostics:
trible team list --pile invitee.pile --team-root <team-root>
trible team show --pile invitee.pile \
  --team-root <team-root> --grant <invitee-grant>

# Sync native collection evidence and service durable WANTs:
trible pile net sync invitee.pile \
  --key invitee.key --team-root <team-root> --grant <invitee-grant> \
  --peers <founder-node-id>
```

`pile net sync` runs until interrupted unless you give it `--duration` or
`--quiescent-for`. Start the founder side against `founder.pile` with the
founder key, team root, and founder grant; it does not need a `--peers` argument
when the invitee is dialing it.

Pass `--delegate` to `team invite` only when the invitee should be able to
issue attenuated child CONNECT grants. Without it, the child may connect but
not delegate. An invite bundle is public and self-contained; possession does
not confer authority because verification binds its leaf to the invitee's
private-key-backed transport identity.

== Diagnostics

`trible pile net status` resolves the named grant from the named pile,
reconstructs its root-to-leaf proof, and checks that the leaf invokes
`CONNECT` for the supplied key on this team's exact authority collection. It
uses the same claim shape as the network handshake. There is no environment-
variable fallback, sentinel credential, implicit team-of-one network
credential, or automatic key creation on this path.

The authority resolver reports malformed, incomplete, or unauthorized
candidate grants without letting one bad occurrence suppress independently
valid grants. This is useful when piles have learned sparse evidence in a
different order.

== Removal is an epoch change

Positive authority is monotone: an accepted grant does not expire or retract
inside the same authority epoch. Durable removal therefore means moving the
relevant team, collection, or key to a successor epoch and enforcing the new
boundary. This cost is deliberate; it keeps proofs portable and makes pile
concatenation ordinary set union instead of hidden last-writer arbitration.

== Reference

  - User chapter: `triblespace-rs/book/src/capability-auth.md`
  - Library: `triblespace_core::authority`
  - Transport: `triblespace_net::host` and
    `triblespace-rs/book/src/distributed-sync.md`

Next stop: [Relations: People and Handle Mappings](wiki:e7e3f672a66b39e0b5b3c0eaf212b1da).
