= Substrate 1/4: What Is a Trible

Everything the faculties store — goals, fragments, messages,
files — decomposes into *tribles*: fixed-width, content-
addressable facts. One trible states one thing about one
entity.

== The shape

A trible is exactly 64 bytes:

```
┌──────────────┬──────────────┬──────────────────────────┐
│ entity (16B) │ attrib (16B) │ value (32B)              │
├──────────────┼──────────────┼──────────────────────────┤
│ who/what     │ which fact   │ inline data, or the hash │
│ it's about   │ kind         │ of a blob that holds it  │
└──────────────┴──────────────┴──────────────────────────┘
```

  - *Entity*: a 128-bit id. Minted randomly (`trible genid`),
    or *derived from content* — same content, same id, on
    every machine, with no coordination.
  - *Attribute*: a 128-bit id naming the fact kind
    (`compass status`, `wiki title`, …). Minted once,
    never guessed.
  - *Value*: 32 bytes. Small values (timestamps, weights,
    short strings, other entity ids) live inline. Anything
    bigger (a document, an image) lives as a blob addressed
    by its 32-byte hash — the trible holds the hash.

== Why fixed-width matters

A fact has exactly one byte representation. There is no
serialization step, no parse step, no "same data, different
JSON". Consequences:

  - *Dedup is free* — same fact, same bytes; storing twice
    is a no-op.
  - *Hashing and signing are canonical* — two agents hashing
    the same knowledge get the same hash.
  - *A fact is its own wire format* — what you store is what
    you send.

== A row is not a fact

Relational rows bundle many assertions; updating one column
rewrites the row. Tribles never bundle: "goal G has status
doing" and "goal G has title X" are separate facts with
separate lifetimes. This is what makes append-only storage
(next fragment) practical rather than painful.

== Further reading

Sibling fragments "Substrate 2/4: The Pile" (wiki:5232ea531fedfcb17bf15e88c3d52a36) and "Substrate 3/4: Monotonic Merge" (wiki:5cc10e2b0263008b261cf8a1ef30bd8c) build on this. The full data-model
reference lives in the `triblespace-rs` book.

Next stop: wiki:5232ea531fedfcb17bf15e88c3d52a36 — Substrate 2/4: The Pile.
