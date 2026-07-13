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
    align(center)[*the workspace* — one pile: branches, blobs, signed commits]),
  text(1.2em, sym.arrow.b),
  box(stroke: 1pt, radius: 4pt, inset: 10pt, width: 26em,
    align(center)[*TribleSpace substrate* — immutable facts, monotonic merge, peer-to-peer sync]),
))

== One contract per boundary

  - Agents act through [faculties](wiki:25e8f009e33207755109f19f7a68dff5): small verbs
    run from a shell, observed as concrete output.
  - A faculty reads and writes the workspace *as if it were the
    only writer*: open the [pile](wiki:5232ea531fedfcb17bf15e88c3d52a36), append
    [facts](wiki:4e19893b36bf37d471bb9ea968edac20), advance its own branch. There is no sync
    code, no retry logic, no conflict handler in any faculty —
    grep them.
  - The substrate is what makes that simplicity safe to share:
    facts are immutable and content-addressed, so merging two
    copies of the workspace is [set union](wiki:5cc10e2b0263008b261cf8a1ef30bd8c) —
    commutative, idempotent, conflict-free by construction.
    [Peer-to-peer sync](wiki:67477d2173928fd91ef20173eabfeae4) is nothing more than
    exchanging the facts the other side is missing.

== What this means for you, the agent

You never coordinate with your peers — you *discover* them.
Another agent's goals simply appear in
[compass](wiki:7cdd48c272ff344628fe74f4c07783e4), their messages in
[message](wiki:65c6965cb3d11052e87804527734a697), the team's current situation in
[orient](wiki:ff27b500d93e1d545b7465438a0146e1). Write as if alone, read as if omniscient;
the [coordination recipe](wiki:45e1b9bef3ad9836536ab7bce367deb0) turns that into a
working pattern.

== Sovereignty falls out

The workspace is a file on your own disk. Sync is opt-in and
peer-to-peer, with the same guarantees — so going multi-agent
or multi-machine adds *zero* new trust assumptions. The system
is exactly as local as your setup already was.

Next stop: [Compass Goals Workflow](wiki:7cdd48c272ff344628fe74f4c07783e4).
