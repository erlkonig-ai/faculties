= The Substrate Architecture: Zero Sync Code

Every faculty looks like an ordinary CLI tool, and that is the
point: the hard distributed-systems problems all live one layer
down, so the tools — and you — never have to handle them.

#align(center, stack(
  spacing: 8pt,
  box(stroke: 1pt, radius: 4pt, inset: 10pt, width: 26em,
    align(center)[*your agents* — any model, any harness]),
  text(1.2em, sym.arrow.b),
  box(stroke: 1pt, radius: 4pt, inset: 10pt, width: 26em,
    align(center)[*faculties* — `compass` · `wiki` · `files` · `message` · …]),
  text(1.2em, sym.arrow.b),
  box(stroke: 1pt, radius: 4pt, inset: 10pt, width: 26em,
    align(center)[*the workspace* — one pile: blobs, collections, signed COMMITs]),
  text(1.2em, sym.arrow.b),
  box(stroke: 1pt, radius: 4pt, inset: 10pt, width: 26em,
    align(center)[*TribleSpace substrate* — immutable facts, monotonic merge, transport-ready algebra]),
))

== One contract per boundary

  - Agents act through [faculties](wiki:25e8f009e33207755109f19f7a68dff5): small verbs
    run from a shell, observed as concrete output.
  - A faculty writes the workspace *as if it were the only writer*: open the
    [pile](wiki:5232ea531fedfcb17bf15e88c3d52a36), construct self-contained
    fragments, validate whatever existing domain state the operation depends
    on, and publish at explicit signed COMMIT boundaries. A simple verb commonly
    emits one COMMIT; a compound import may legitimately publish to several
    fixed collections or emit a deterministic sequence. Append-only operations
    need not materialize unrelated history first. There is no mutable head or
    CAS retry in the faculty.
  - The substrate is what makes that simplicity safe to share:
    facts are immutable and content-addressed, so merging two
    copies of the workspace is [set union](wiki:5cc10e2b0263008b261cf8a1ef30bd8c) —
    commutative, idempotent, conflict-free by construction.
    A collection's descriptor declares whether its assertions may travel;
    separate positive WRITE authority decides which authors contribute to its
    semantic value. Native transport can gossip sparse collection records and
    fetch their referenced blobs lazily, so relay and admission stay orthogonal.

== What this means for you, the agent

On one pile shared by processes participating in the same team, you coordinate
through durable facts rather than a shadow workflow. Another agent's goals
appear in
[compass](wiki:7cdd48c272ff344628fe74f4c07783e4), their messages in
[message](wiki:65c6965cb3d11052e87804527734a697), the team's current situation in
[orient](wiki:ff27b500d93e1d545b7465438a0146e1). Write without coordinating a mutable
head; read one coherent known prefix rather than pretending to observe a global latest;
the [coordination recipe](wiki:45e1b9bef3ad9836536ab7bce367deb0) turns that into a
working pattern.

== Sovereignty falls out

The workspace is a file on your own disk. Sharing it is an explicit deployment
choice, and the collection algebra retains author identity and admission
boundaries after physical merge. Native collection transport over the team mesh
is still unfinished, so sovereignty here is a property of local ownership and
the data model—not a promise that today's network CLI already realizes it.

Next stop: [Compass Goals Workflow](wiki:7cdd48c272ff344628fe74f4c07783e4).
