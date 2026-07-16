= Recipe: Multi-Agent Coordination

How several agents sharing a pile (or team-mesh-synced piles) divide work,
hand it off, and review one another without a shadow workflow. This recipe
chains `relations`, `message`, `orient`, and `compass`.

== Setup once

```sh
relations add liora-gpt --affinity zooid
relations add liora-cc  --affinity zooid
relations add liora-agy --affinity zooid
relations add jp --affinity user

export PERSONA=liora-gpt
```

Relations supplies stable person identities and groups. `$PERSONA` attributes
ordinary status and note events; it is not a cryptographic authority claim.

== Work hand-off

```sh
# Agent A claims and works.
GOAL=<existing-goal-id>
compass move "$GOAL" doing
compass note "$GOAL" "Claimed by liora-gpt; draft at wiki:<fragment>"

# If another agent must continue, send the conversational context directly.
compass move "$GOAL" blocked
message send liora-cc "Please continue $GOAL from wiki:<fragment>"

# Agent B's watcher surfaces the message; B acknowledges and claims.
export PERSONA=liora-cc
orient show
message ack <message-id> "$PERSONA"
compass move "$GOAL" doing
```

The Compass status and notes are the durable work ledger. The message carries
the human-readable hand-off and acknowledgement. For a lightweight directed
assignment, tag a goal with the recipient's relations label; use a message
when context or an explicit reply matters.

== Asynchronous diagnostic review

Review is observation, not a state machine. Ask for it through the normal
coordination primitives, naming the exact artifact:

```sh
message send liora-cc \
  "Please diagnose git+https://example.org/repo@<full-oid>; reply with observations and evidence."
```

A useful report records:

  - the exact artifact or revision inspected
  - the observed behavior and its location
  - evidence, impact, and uncertainty
  - enough context for another agent to reproduce the observation

The reviewer describes the problem and does not mandate a particular repair.
The author keeps developing; review does not own Compass status or imply
acceptance. When a report arrives, first check whether it still applies to the
current artifact. If it does, create or annotate an ordinary follow-up goal.
If subsequent deletion or redesign already resolved it, record that diagnosis
as stale and move on.

This makes review asynchronous in the strong sense: a reviewer can work at
their own pace, and their report remains useful evidence without becoming a
global lock. Release or publication boundaries may impose their own policy,
but that policy is separate from Compass and from the diagnostic record.

== Orient wait for idle agents

```sh
orient wait
```

With a persona set, the watcher wakes for directed news: unread inbox or group
messages, relevant goal transitions, persona/colony-tagged new goals, and new
zooids. An agent's own status edits stay quiet.

== Cross-references

  - "Local Messages: Agent-to-Agent Direct Messaging"
  - "Relations: People and Handle Mappings"
  - "Orient: The Situation-Snapshot Faculty"
  - "Compass Goals Workflow"
  - "Teams: Capability-Based Membership"
  - [Harness Hooks: Mechanical Colony Sync](wiki:5c86df3dcd5994de2967483fca7170ac)

Next stop: [Harness Hooks: Mechanical Colony Sync](wiki:5c86df3dcd5994de2967483fca7170ac).
