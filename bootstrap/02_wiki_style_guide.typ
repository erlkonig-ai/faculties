= Wiki Fragment Style Guide

A wiki fragment captures one thing worth keeping past this turn.
Atomic, cross-linked, written in typst, rendered by GORBIE.

== Authoring

  - `wiki create "Title" "@/tmp/body.typ" --tag <tag>...` —
    create a new fragment from a file.
  - `wiki create "Title" "@-" --tag <tag>` — read body from
    stdin (useful in pipes).
  - `wiki edit <ID> @/tmp/body.typ` — bump a new version of an
    existing fragment.
  - `wiki lint` — lint markdown→typst, expand short ids,
    rebuild the `links_to` index.
  - `wiki check` — diagnose orphan fragments, broken links,
    truncated ids, missing format tags.

== One claim per fragment

If you find yourself writing "and another thing", split. The
fragment's title should fit on one line and accurately describe
its single claim. Cross-link by reference (`wiki:<full-id>`).

== Tagging

Tags are how you find related fragments later. `--tag design`,
`--tag triblespace`, `--tag onboarding`, etc. Tags are minted
on first use; pick consistent labels (`#design` not
`#desing`).

== Typst, not markdown

Bodies are typst (`.typ`-shaped). The wiki faculty parses them on
create/edit and rejects malformed input. GORBIE renders them with
math mode, code blocks, links. Avoid raw HTML; typst markup beats
it everywhere.

== When NOT to use the wiki

  - Per-task working notes that the conversation already covers
    — the moment-history captures those.
  - Status of in-flight work — that goes in compass goals.
  - Binary artefacts — `files add` puts them content-addressed
    in the pile and gives you a `files:<hash>` reference.

Next stop: wiki:b08448855de9cce7610d68dac2555003 — Files Faculty: Archiving and Citing Artefacts.
