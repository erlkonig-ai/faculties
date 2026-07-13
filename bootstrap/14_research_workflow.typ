= Recipe: Research Workflow

A worked recipe for the most common agent task: pursue a question,
archive the source material, write up the finding. Chains four
faculties — compass, web, files, wiki — into one durable trail.

== Why a recipe

Per-faculty docs answer "what does X do." Recipes answer "what do
I run, in order, when I want to *accomplish concrete goal*." The
faculty model is composable but the composition isn't obvious
from the individual `--help` outputs.

== The recipe

```sh
# 1. Frame the question as a compass goal.
#    The goal is your container — every artefact below cites it.
GOAL=$(compass add "Investigate <topic>" \
  --tag research \
  --note "Hypothesis: ..." \
  | grep -oE '[0-9a-f]{32}')
compass move "$GOAL" doing

# 2. Search.
web search "<query>"

# 3. For each promising result, archive the raw bytes.
#    Multiple `files fetch` calls are fine — content-
#    addressing dedupes if you accidentally fetch the same URL
#    twice.
files fetch https://arxiv.org/pdf/<id>.pdf
# → files:<hash>   (use this hash below)

# 4. Take notes as fragments while you read.
#    Cite the archived file by hash.
wiki create "<finding title>" "@-" \
  --tag research --tag <topic> <<EOF
= <finding title>

Per [Smith 2024 §3.2](files:<hash>), <claim>. The proof
relies on <observation>; key assumption is <X>.

Open: does the bound tighten when <Y>?
EOF

# 5. Cross-link new fragments back to the goal.
compass note "$GOAL" "Wrote up finding: see wiki:<frag-id>"

# 6. Record the outcome. Pure lookup/bookkeeping can close directly.
#    A result that will drive a main-bound artefact enters exact review.
compass note "$GOAL" "Conclusion: ..."
export PERSONA=liora-gpt # each reviewer uses their own relations label
compass review open "$GOAL" \
  --target 'git+https://example.org/repo@<full-commit-oid>' \
  --review-group review-triad \
  --override-authority jp
# Three independent `compass review submit <request> ...` passes,
# then `compass review settle <request>`.
```

== Why each step

  - *Compass goal first*: the goal id is a stable handle for
    every cross-reference. If you skip this and just open a
    fragment, you have to retroactively link findings back later.
  - *web search before files fetch*: web gives
    cleaned text + provider-quality results;
    files grabs raw bytes for durable citation.
  - *Fragment per finding, not per session*: atomic fragments
    cross-link cleanly and survive session boundaries. A
    "session log" fragment that tries to capture everything is
    a leaky abstraction.
  - *Outcome note before settlement*: the outcome line is
    what future-you (or another agent) will see when scanning
    the goal or reviewing its candidate. Make it useful — what did
    you learn, what's still open. Review actions themselves are the
    ledger: open enters `review`; settle enters `done`.

== Skipping steps

  - For fast lookup ("just need the dates", "what's the URL of
    the paper I read last week"), skip compass. Run
    `wiki search` or `files search` directly.
  - For one-off facts you'll never cite again, skip
    files and just paste the relevant text into a wiki
    fragment with the URL inline. Use judgement: if you'll cite
    the source from another fragment, archive it.

== Variant: hybrid with codex

For literature trawls (read 30 papers, summarise each), launch
codex on step 4 and integrate its output as one fragment per
paper. See "When to Use Codex (and When Not To)" for the launch
pattern. The compass goal still owns the trawl; codex is the
data-plane that fills in the per-paper fragments.

== Cross-references

  - "Web: Search and Fetch Through Provider APIs"
  - "Files Faculty: Archiving and Citing Artefacts"
  - "Wiki Fragment Style Guide"
  - "Compass Goals Workflow"
  - "When to Use Codex (and When Not To)"

Next stop: [Recipe: Multi-Agent Coordination](wiki:45e1b9bef3ad9836536ab7bce367deb0).
