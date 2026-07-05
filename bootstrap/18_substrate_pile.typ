= Substrate 2/4: The Pile

A pile is one file holding everything an agent knows: every
trible, every blob, every branch head. It is *append-only* —
bytes are added at the end, never rewritten.

== The shape

```
self.pile
┌────────────────────────────────────────────────┐
│ blob │ blob │ commit │ blob │ commit │ commit │ ──▶ append
└────────────────────────────────────────────────┘
   ▲                       ▲
   content-addressed       Ed25519-signed,
   (hash = identity)       form branch histories
```

  - *Blobs* carry the data: trible sets, documents, files.
    Each is addressed by its hash — the pile is a
    content-addressed store in a single file.
  - *Commits* are signed pointers: "branch `wiki` now
    includes this set of facts". Each faculty owns its
    branch (`compass`, `wiki`, `files`, …) and they merge
    independently.

== Nothing is ever deleted

Changing your mind appends a *new* fact rather than editing
an old one. Readers pick the latest fact per key by its
time coordinate (the coordinate-and-cursor pattern); the old
fact stays — history is exhaust from the workflow, never a
separate bookkeeping step.

This is what makes the audit trail of `compass` /
`wiki` / `decide` trustworthy: there is no API to
falsify the past, by construction.

== Consequences of append-only + content-addressing

  - *Crash-safe*: a torn write is detected on load and
    reported loudly; everything before it is intact. Cutting
    the torn tail off is a separate, explicit, destructive
    step (`trible pile amputate`), never part of opening.
  - *Trivially mergeable*: `cat a.pile >> b.pile` is a
    legitimate first step of merging two piles — duplicate
    blobs collapse because identical content has identical
    hashes.
  - *Syncable*: a peer needs only the blobs it's missing —
    which both sides can compute from hashes alone.

== Further reading

[Substrate 1/4: What Is a Trible](wiki:4e19893b36bf37d471bb9ea968edac20) covers the facts inside
the blobs; [Substrate 3/4: Monotonic Merge](wiki:5cc10e2b0263008b261cf8a1ef30bd8c) covers why
combining piles never conflicts.

Next stop: [Substrate 3/4: Monotonic Merge](wiki:5cc10e2b0263008b261cf8a1ef30bd8c).
