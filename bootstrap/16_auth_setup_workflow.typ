= Recipe: Share a Collection Between Agents

Collection synchronization has no ambient team or CONNECT grant. Every exact
descriptor carries independent READ and WRITE policies, and `pile net sync`
repairs only the handles named by its operator. The iroh transport already
authenticates each endpoint key.

This recipe gives a second node READ and WRITE access to one collection, seeds
the descriptor and proof records on both sides, then starts repair.

== Prepare one portable bootstrap pile

```sh
# On the founder, initialize a durable signer and the named collection.
trible pile create mesh-bootstrap.pile
trible pile signing-key init mesh-bootstrap.pile --key root.key
COLLECTION=$(trible pile collection init mesh-bootstrap.pile message --key root.key)

# On the invitee, initialize its own durable signer beside its future pile and
# send only the printed public key to the founder.
trible pile signing-key init invitee.pile --key invitee.key
trible pile net identity --key invitee.key

# The founder can use the same durable signer for COMMITs and its iroh endpoint.
trible pile net identity --key root.key

# READ authorizes disclosure and repair for this exact descriptor.
trible pile collection grant-read mesh-bootstrap.pile "$COLLECTION" \
  <invitee-public-key> --key root.key

# WRITE authorizes the invitee's signed COMMITs in collection snapshots.
trible pile collection grant-write mesh-bootstrap.pile "$COLLECTION" \
  <invitee-public-key> --key root.key
```

The descriptor and proof records are ordinary grow-only pile state. Seed each
replica by copying the bootstrap pile before it diverges, or concatenate it
into an existing stopped pile:

```sh
cat mesh-bootstrap.pile >> founder.pile
cat mesh-bootstrap.pile >> invitee.pile
```

Concatenation is set union during replay. Do not run legacy branch
consolidation afterward, and do not use a destructive source-deletion option.

== Activate live repair

```sh
# Founder serves and pulls this collection.
trible pile net sync founder.pile \
  --key root.key --collection "$COLLECTION" \
  --peers <invitee-endpoint-ticket-or-id> --payload demand

# Invitee runs the symmetric side.
trible pile net sync invitee.pile \
  --key invitee.key --collection "$COLLECTION" \
  --peers <founder-endpoint-ticket-or-id> --payload demand
```

`--direction read-only` pulls without serving; `write-only` serves without
pulling; the default is bidirectional. `--payload demand` exchanges semantic
collection evidence and satisfies durable collection-scoped WANTs as needed.
Use `--payload full` only when this node deliberately mirrors the admitted
resident blob closure. `--duration` and `--quiescent-for` make a rehearsal
bounded; otherwise sync runs until interrupted.

Use the same key paths as `TRIBLESPACE_KEY` (or pass them with a faculty's
`--key`) when publishing. The WRITE grant is about that COMMIT signer; the READ
grant is what lets the same authenticated endpoint receive collection state.

== Why the boundaries matter

  - Knowing a collection handle is not READ authority.
  - Routing, gossip, DHT presence, and local WANTs grant no capability.
  - WRITE decides which signed COMMITs contribute to a snapshot; local storage
    may still retain inactive evidence.
  - READ is checked for the exact descriptor before semantic disclosure. Blob
    handles remain bearer capabilities only inside that authorized exchange.
  - Capability proofs and claim blobs are portable grow-only evidence. Ending
    an unexpired grant requires a deliberate new policy/key epoch rather than a
    hidden mutable revocation list.

See `triblespace-rs/book/src/capability-auth.md` and
`triblespace-rs/book/src/distributed-sync.md` for the complete model.

Next stop: [Getting Started: Your First Hour (tour complete)](wiki:44d63d174814371c7468a3e604ed2303).
