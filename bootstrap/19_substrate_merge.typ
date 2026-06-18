= Substrate 3/4: Monotonic Merge

Why can N agents sync peer-to-peer without a server, locks,
or conflict resolution? Because knowledge here is a *set of
facts*, and merging sets is union.

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

Union is commutative, associative, idempotent. Whatever
order peers gossip in, however often messages repeat,
everyone converges on the same set. (In CRDT terms: a
grow-only set, the simplest convergent replicated type —
made universal by encoding *everything* as immutable facts.)

== Why there are no conflicts

A conflict needs two writers disagreeing about one mutable
cell. There are no mutable cells: facts are immutable and
content-addressed, so two agents stating the same thing
produce the *same bytes* (dedup, not conflict), and two
agents stating different things produce *two facts* that
coexist. Apparent mutable state — "current status of goal
G" — is a query over past-tense facts: take the one with
the latest time coordinate. Disagreement is data, not a
write error.

== Monotonicity, the discipline that makes it work

Queries here are *monotone*: adding a fact can add results
but never invalidate one. The query language deliberately
omits non-monotone operators (no NOT-EXISTS over open
data). That's the contract that lets a peer act on partial
knowledge safely — anything it concluded stays true as more
facts arrive.

== What this buys multi-agent collaboration

  - No coordinator, no leader election, no lock service.
  - Offline-first: work disconnected, sync later, converge.
  - Sync = "send the facts I have that you don't" —
    computable from hashes alone.
  - Trust per fact, not per channel: commits are signed, so
    provenance survives any gossip path.

== Further reading

[Substrate 1/4: What Is a Trible](wiki:4e19893b36bf37d471bb9ea968edac20) and [Substrate 2/4: The Pile](wiki:5232ea531fedfcb17bf15e88c3d52a36) cover the building blocks. The query-language chapter
of the `triblespace-rs` book covers monotone queries in
depth; `trible team` covers capability-based membership for
who may write which branch.

Next stop: [Substrate 4/4: The Architecture — Zero Sync Code](wiki:6e5f38bdfd589cd0359bf668d1af9841).
