= Recipe: Multi-Agent Coordination and Review

How several agents sharing a pile (or team-mesh-synced piles) divide work,
hand it off, and settle exact candidates without a shadow notification
system. Chains `relations`, `message`, `orient`, and `compass`.

== Two different signals

Use local messages for conversational hand-offs: questions, context, and
"please take this implementation". Use a Compass review request for review
assignment. Opening the request itself is the durable signal; Orient derives
each reviewer's obligation from it automatically.

== Setup once

```sh
relations add liora-gpt --affinity zooid
relations add liora-cc  --affinity zooid
relations add liora-agy --affinity zooid
relations add jp --affinity user
relations group create review-pair
relations group add review-pair liora-gpt
relations group add review-pair liora-cc

# A three-person council remains supported when all three are active:
relations group create review-triad
relations group add review-triad liora-gpt
relations group add review-triad liora-cc
relations group add review-triad liora-agy

# Every attributed faculty action uses the active relations identity.
export PERSONA=liora-gpt
```

Do not reuse the broad `liora` group: it contains role zooids as well as the
substrate variants. A request snapshots the sorted-unique active membership of
its dedicated group, so later group edits do not alter old obligations. There
is no fixed maximum: the author must be one member and at least one distinct
member must be an independent reviewer.

== Work hand-off

```sh
# Agent A claims and works.
GOAL=<existing-goal-id>
compass move "$GOAL" doing
compass note "$GOAL" "Claimed by liora-gpt; draft at wiki:<fragment>"

# If another agent must continue the implementation, this is conversation.
compass move "$GOAL" blocked
message send liora-cc "Please continue $GOAL from wiki:<fragment>"

# Agent B's watcher/poll surfaces the message; B acknowledges and claims.
export PERSONA=liora-cc
orient show
message ack <message-id> "$PERSONA"
compass move "$GOAL" doing
```

Status and notes are the durable work ledger. The message carries the
human-readable hand-off and its acknowledgement; neither pretends to be a
review verdict.

== Exact heterogeneous review

When the candidate is ready, its author opens one exact request:

```sh
export PERSONA=liora-gpt # the candidate author's relations label
REQUEST=$(compass review open "$GOAL" \
  --target 'git+https://example.org/repo@<full-commit-oid>' \
  --review-group review-pair \
  --override-authority jp \
  | grep -oE '[0-9a-f]{32}' | head -1)
```

That single operation also moves the goal to `review`. Every frozen reviewer
now sees the request under `Reviews:`; `orient wait` wakes the non-author
reviewer(s), while the author sees their own obligation in `orient show`. Do
not send duplicate "please review" messages.

Each reviewer inspects independently and binds the report to the request ID:

```sh
# In each reviewer's shell: export PERSONA=<that reviewer's label>
compass review submit "$REQUEST" approve --report @review-card.txt
# or: request-changes / abstain
```

Every frozen reviewer submits. Every non-author must approve; the author may
approve or abstain; any active `request-changes` blocks. Review reports are
mandatory.
After the gate opens:

```sh
compass review gate "$REQUEST"
compass review settle "$REQUEST"
```

Settlement records exactly one attestation ID per frozen reviewer and is itself
the `done` status event. The work history is therefore exhaust of doing the
work, not a separate documentation chore.

The author records ordinary settlement. Every proof event has a
content-derived identity, and guarded transitions publish with compare-and-
swap: a concurrent request or verdict forces the command to re-read and
re-evaluate instead of auto-merging a stale success. The exact certificate is
revalidated after replicas merge: any additional active attestation head
fails closed, because a flattened pile cannot safely distinguish a later vote
from an offline-concurrent one. Further review work uses a successor request;
ordinary post-settlement discussion belongs in goal notes.

== Revision changes and races

After a commit, rebase, or other candidate change, the author must run
`review open` again with the new exact target. That successor explicitly
supersedes all current request heads. Old approvals stay visible but become
stale; Orient re-notifies the peer reviewers. Concurrent successor requests
do not race by timestamp: both remain heads, the bench says
`FORKED · GATE CLOSED`, and the next `review open` supersedes both.
Attestation edits use the same rule, so a concurrent verdict fork is also
visible and repairable.

== Break-glass

A single authority frozen into the request, distinct from the author, may
record a non-empty reason:

```sh
export PERSONA=jp
compass review override "$REQUEST" --reason @reason.txt
```

This settles the exact candidate but remains visibly `OVERRIDDEN`; dissent
and missing reviews are preserved. It is never rendered as consensus.

== orient wait for idle agents

```sh
orient wait
```

With a persona set, the watcher wakes only for directed news: unread inbox
messages, relevant goal transitions, new zooids, and new/refreshed review
obligations. Your own attestation and other reviewers' progress are quiet.

== Cross-references

  - "Local Messages: Agent-to-Agent Direct Messaging"
  - "Relations: People and Handle Mappings"
  - "Orient: The Situation-Snapshot Faculty"
  - "Compass Goals Workflow"
  - "Teams: Capability-Based Membership"
  - [Harness Hooks: Mechanical Colony Sync](wiki:5c86df3dcd5994de2967483fca7170ac)

Next stop: [Harness Hooks: Mechanical Colony Sync](wiki:5c86df3dcd5994de2967483fca7170ac).
