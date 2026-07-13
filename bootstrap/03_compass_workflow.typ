= Compass Goals Workflow

`compass` is the goal/task tracker. Use it instead of
Claude Code's TaskCreate/TaskUpdate — compass goals persist
across sessions and merge between agents; the harness's task
list does neither.

== Statuses

  - `todo` — queued, not started
  - `doing` — actively in progress
  - `blocked` — waiting on something external
  - `review` — bound to an exact candidate awaiting heterogeneous settlement
  - `done` — finished, with an outcome note

Stick to those five unless there's a strong reason to introduce
another.

== Daily flow

  + `compass list` — see your active goals
  + Pick one, `compass move <id> doing` — claim it
  + Add notes as you decide things: `compass note <id> "..."`
  + Add a final note recording the outcome
  + For ordinary bookkeeping goals: `compass move <id> done`
  + For anything bound for a project's main branch: use the
    settlement flow below
  + Repeat

== Exact review settlement

Review is not a free-form status. `review open` atomically binds an
immutable artifact revision, freezes exactly three reviewer identities,
and moves the goal to `review`:

```sh
# Every review action is attributed to the active relations identity.
export PERSONA=liora-gpt

compass review open "$GOAL" \
  --target 'git+https://example.org/repo@<full-commit-oid>' \
  --review-group review-triad \
  --override-authority jp
# → request id
```

The named group is read once. Its three active person IDs are copied into the
request, so later membership changes cannot rewrite history. The author
must be one of the three. Soft retirement prevents future assignment but
does not revoke a submit/settle/override role already frozen into a request.
Create a dedicated `review-triad` group; the general `liora` broadcast group
contains role zooids and is not a roster.

The request appears automatically in every reviewer's `orient show`.
`orient poll` and `orient wait` wake the two peer reviewers; the author made
the request and sees their own outstanding attestation in the snapshot. No
hand-written notification message is needed. Reviewers deliberately attest
the *request id*, not the goal id, each with `$PERSONA` set to their own label:

```sh
compass review submit "$REQUEST" approve \
  --report @review-card.txt
```

Verdicts are `approve`, `request-changes`, or `abstain`. Reports are
mandatory: this is evidence, not ceremonial voting. All three must submit;
both non-authors must approve; the author may approve or abstain; any
`request-changes` closes the gate.

```sh
compass review status "$REQUEST"
compass review gate "$REQUEST"       # non-zero while closed
compass review settle "$REQUEST"     # records proof + moves goal to done
```

Requests and attestations use explicit `supersedes` edges. After a commit,
rebase, or other candidate change, run `review open` again with the new exact
target. That successor request supersedes every current request head, makes
the old evidence stale, and automatically re-notifies the peer reviewers.
Concurrent successors remain an honest visible fork and fail closed; the
next open/submit supersedes all fork heads to repair it. No mutable "current"
or "approved" flag exists.

Request, attestation, override, and settlement IDs are derived from all of
their proof-defining fields. Append-only back-patching therefore makes an
event non-canonical and closes the gate instead of rewriting what it meant.
Guarded writes use compare-and-swap: if the Compass branch changes between
the check and publish, the command re-reads the merged state and re-evaluates
before committing. After replicas merge, an ordinary certificate remains
valid only while its three sealed attestations are the unique active heads.
An offline-concurrent vote therefore fails closed instead of being mistaken
for later discussion. Put post-settlement discussion in goal notes; any new
review evidence or changed work opens an explicit successor request.

A single frozen override authority, independent from the author and acting
under their own `$PERSONA`, may use
`compass review override "$REQUEST" --reason @reason.txt`. The bench keeps
the closed review in history, labels it `OVERRIDDEN`, preserves every blocker,
and never displays it as unanimous approval. Once a goal has structured
review history, every raw `compass move` is rejected; successor requests and
settlements are the only transitions that can preserve the exact proof.

The normal target parser accepts full Git object IRIs and recognized content
hash schemes. An opaque IRI requires the conspicuous
`--unsafe-opaque-target` acknowledgement because Compass cannot prove that a
generic URL is immutable. Persona labels are currently cooperative relations
claims, not cryptographic signatures; intrinsic identity protects proof
content, while authenticated actor capabilities remain a separate layer.

== Hierarchy

`compass add "<title>" --parent <id>` creates a sub-goal. Use
this when a goal naturally breaks into 3+ steps you'll want to
track separately. Don't sub-goal trivial steps — the conversation
itself is the right level for "and now do X".

== Tags

Compass tags work like wiki tags. Common ones:
`#meta`, `#bootstrap`, `#parking` (see Scope Control below),
plus project-specific tags (`#liora` in the Liora project,
`#deploy` for ops work, etc.).

== Scope control: parking lot

Mid-task ideas that would take >2 minutes go in compass with
a `#parking` or `#later` tag. Then *return to the current goal*.
Near the end of a session, do a parking-lot sweep: promote
0–2 parked items to active, leave the rest.

The parking discipline keeps the agent from infinitely-context-
switching and producing nothing. Compass is the queue; the
conversation is the executor.

== When NOT to use compass

  - In-conversation TodoWrite-style step planning is fine for
    "the next 20 minutes" — compass is for goals you'd want to
    pick up later, including in a future session.
  - Pure scratch state ("what was I about to do") — that's the
    conversation itself.

Next stop: [Wiki Fragment Style Guide](wiki:82129c70b693f7e2d781d78ac5efbb86).
