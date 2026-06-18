= Recipe: Multi-Agent Coordination

How two agents working on the same pile (or on team-mesh-synced
piles) hand work back and forth without stepping on each other.
Chains `relations`, `local_messages`, `orient`, and `compass`.

== Why a recipe

Each faculty in isolation is obvious. The non-obvious thing is
the *handshake order* — which faculty signals which event so the
other agent picks it up. Skip steps and you get racy work
(both agents claiming the same goal) or silent drops (a message
that was sent but never read).

== The recipe — Agent A hands work to Agent B

```sh
# Setup (once, on each pile):
relations add jp --display-name "JP" --affinity "user"
relations add agent-b --display-name "Agent B" --affinity "teammate"

# Agent A: claim the goal first.
GOAL=<existing-goal-id>
compass move $GOAL doing
compass note $GOAL "Claimed by agent-a, draft pending"

# Agent A: do partial work, then prepare hand-off.
compass note $GOAL "Draft at wiki:<frag-id>; need agent-b to verify the calculation"
compass move $GOAL blocked   # signals "external dependency"
local_messages send agent-b "Goal $GOAL ready for review — see wiki:<frag-id>"

# Agent B (later, possibly different session):
orient show                  # surfaces the new message + blocked goal
local_messages ack <msg-id>  # read receipt
compass move $GOAL doing
compass note $GOAL "Picked up by agent-b for review"

# Agent B does the work, hands back:
compass note $GOAL "Verified §3.2; numbers correct. Pushed back to A."
local_messages send agent-a "Done with review on $GOAL"
compass move $GOAL doing     # NOT done — A still owns the goal
```

== Why each step

  - *relations once per pile*: handles resolve through this
    registry. Without it, `local_messages send agent-b ...`
    can't address the recipient.
  - *Status change before sending the message*: `compass move $GOAL blocked` first.
    the status change is the durable signal; the message is
    the polite notification. If the message is missed, the next
    `orient show` from B still surfaces the blocked goal.
  - *Notes on every transition*: the goal's history is the
    audit trail. "Claimed by", "Draft at", "Verified", "Pushed
    back" — each note records what happened and who did it.
  - *Don't move to done across the handshake*: only the agent
    who *originated* the goal should mark it done. B verifies
    and hands back; A confirms and closes.

== orient wait for idle agents

If Agent B is running a `/loop` or sitting idle, replace
`orient show` with `orient wait` — that blocks until any
relevant branch changes, including gossip-merged remote writes
through `pile net sync`.

```sh
# Agent B's idle loop:
while true; do
  orient wait    # blocks until something arrives
  # ...handle whatever showed up...
done
```

== Conflict resolution

Pile branches are append-only with `cat` union for compass and
local-messages, so concurrent writes never overwrite. Two agents
both moving the same goal to `doing` produces two status events
in chronological order; `compass list` shows the latest.

For genuine ambiguity ("we both started working on this"), the
fix is a quick `local_messages send <other> "I'm taking this
one — you grab X"` — a coordination layer the system supports
but doesn't enforce.

== Cross-references

  - "Local Messages: Agent-to-Agent Direct Messaging"
  - "Relations: People and Handle Mappings"
  - "Orient: The Situation-Snapshot Faculty"
  - "Compass Goals Workflow"
  - "Teams: Capability-Based Membership" — for inter-pile sync
    over a real network (gossip + DHT), the auth-arc tools
    underneath this recipe.

Next stop: [Recipe: Auth Setup for a Multi-Agent Team](wiki:d06247b9d9183721e47a2940806e5d7f).
