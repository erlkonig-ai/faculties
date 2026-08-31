= Substrate 2/4: The Pile

A pile is one file holding everything an agent knows: every trible, every blob,
and the grow-only collection calculus that authorizes them. It is *append-only* —
bytes are added at the end, never rewritten.

== The shape

```
self.pile
┌────────────────────────────────────────────────┐
│ blob │ blob │ COMMIT │ blob │ MERGE │ COMMIT │ ──▶ append
└────────────────────────────────────────────────┘
   ▲                       ▲
   content-addressed       signed membership and
   (hash = identity)       reproducible equations
```

  - *Blobs* carry the data: trible sets, documents, files.
    Each is addressed by its hash — the pile is a
    content-addressed store in a single file.
  - A signed *COMMIT* says "this canonical fact archive is a member of this
    exact collection". The collection is named by a self-describing descriptor
    containing its name, member encoding, and independent READ and WRITE
    policies—not by a mutable pointer.
  - Unsigned *MERGE* and *DERIVE* records describe reproducible algebraic work:
    moving within a collection by union, or across collections by a canonical
    homomorphism. They accelerate reads but grant no publication authority.

== Published facts are never overwritten in place

Changing your mind publishes a new immutable state or event rather than editing
an old one. When a domain needs change, it represents the relationship
explicitly—for example Wiki revisions form a supersession DAG whose complete
frontier remains visible. There is no substrate-wide last-writer-wins rule. The
old fact remains in the append-only source pile: history is exhaust from the
workflow, never separate bookkeeping.

Strictly valid COMMITs are conservative retention roots for their resident data
and attachment closure. Local storage is still manageable: conservative GC can
rewrite retained state into a new pile, and explicit destructive repair can
amputate a torn tail. Those are storage-policy operations, not silent mutation
of a published fact.

== Consequences of append-only + content-addressing

  - *Crash-safe*: a torn write is detected on load and
    reported loudly; everything before it is intact. Cutting
    the torn tail off is a separate, explicit, destructive
    step (`trible pile amputate`), never part of opening.
  - *Trivially mergeable*: concatenation unions the immutable blob and native
    collection-record sets; duplicate content collapses by identity. Retired
    mutable pin logs are not part of this native convergence claim. Physical
    presence is not admission: current faculties materialize only strictly
    valid COMMITs whose authors have exact positive WRITE authority.
  - *Transport-capable algebra*: operators explicitly activate exact collection
    handles. READ proofs govern disclosure, while WRITE proofs independently
    decide semantic admission. Referenced blobs remain lazy and WANTable, so
    replicas can exchange evidence before paying for its complete closure.

== Further reading

[Substrate 1/4: What Is a Trible](wiki:4e19893b36bf37d471bb9ea968edac20) covers the facts inside
the blobs; [Substrate 3/4: Monotonic Merge](wiki:5cc10e2b0263008b261cf8a1ef30bd8c) covers why
combining piles never conflicts.

Next stop: [Substrate 3/4: Monotonic Merge](wiki:5cc10e2b0263008b261cf8a1ef30bd8c).
