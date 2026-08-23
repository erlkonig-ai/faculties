= Substrate 3/4: Monotonic Merge

Why can independently extended pile states under one team converge
without a mutable coordinator once they are exchanged? Because native storage
exposes grow-only sets of blobs, signed COMMIT assertions, and reproducible
equations. Within each team-rooted collection, the semantic value is a union of
fact archives signed by keys with exact positive WRITE authority. COMMITs from
unauthorized keys can coexist in the physical pile while remaining inert to the
current faculty view.

== The shape

```
agent A's facts        agent B's facts
┌─────────────┐       ┌─────────────┐
│ {f1, f2, f3}│       │ {f2, f4}    │
└──────┬──────┘       └──────┬──────┘
       └──────── union ──────┘
                  ▼
        ┌──────────────────┐
        │ {f1, f2, f3, f4} │   ← same result in ANY order,
        └──────────────────┘     merged ANY number of times
```

Union is commutative, associative, and idempotent. Readers using the same exact
collection descriptor, author key, admitted record set, and required blob
closure compute the same value regardless of arrival order or duplication.
Different author/admission views or missing blobs remain explicit boundaries,
not hidden last-writer arbitration.

== Why there are no conflicts

A conflict needs two writers disagreeing about one mutable cell. There are no
mutable cells: facts are immutable and content-addressed, so two agents stating
the same thing produce the *same bytes* (dedup, not conflict), and two agents
stating different things produce *two facts* that coexist. Each faculty gives
its apparent mutable state explicit domain semantics: a revision DAG may expose
two concurrent frontier states, while an event ledger may reduce observations
by a declared ordering. Disagreement is data, not a write error.

== Monotonicity at the fact-query layer

The positive constraint language is monotone over a supplied fact set: adding
a fact can add matches but does not erase an existing match. It deliberately
does not smuggle closed-world negation into an open dataset. Faculty read models
may still compute explicitly non-monotone projections such as a revision DAG's
maximal frontier or the latest checkpoint under a declared total order. Those
semantics live in the domain model; they are not ambient storage arbitration.

== What this buys multi-agent collaboration on shared or merged storage

  - No coordinator, no leader election, no lock service.
  - Offline construction followed by deterministic convergence once the same
    authorized record and blob closure is present.
  - Publication reach is part of the immutable collection descriptor. A peer
    relays a COMMIT only when it can resolve that descriptor and recognizes its
    declared reach law; a missing or unknown descriptor is a refusal.
  - Gossip carries sparse signed evidence, not permission or automatic
    replication. Referenced blobs remain lazy until local WANT policy asks for
    them.
  - Trust per assertion, not per channel: COMMITs are signed, so provenance
    survives any gossip path. Semantic admission still applies exact positive
    WRITE authority when materializing the collection view.

== Further reading

[Substrate 1/4: What Is a Trible](wiki:4e19893b36bf37d471bb9ea968edac20) and [Substrate 2/4: The Pile](wiki:5232ea531fedfcb17bf15e88c3d52a36) cover the building blocks. The query-language chapter
of the `triblespace-rs` book covers monotone queries in
depth; native collection publication binds each COMMIT to an exact descriptor
and author key. The descriptor's reach law governs redistribution, while the
collection's authority observation governs which authors contribute to its
semantic value.

Next stop: [Substrate 4/4: The Architecture — Zero Sync Code](wiki:6e5f38bdfd589cd0359bf668d1af9841).
