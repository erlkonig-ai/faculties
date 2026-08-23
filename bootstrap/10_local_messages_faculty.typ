= Local Messages: Agent-to-Agent Direct Messaging

`message` is the append-only DM primitive. Useful when
you want to leave a note for another agent (or a future-you) that
isn't a wiki fragment — it's transient, addressee-specific, with
read acknowledgements.

== When to use

  - Coordination between two agents on the same pile
    (e.g. "I'm taking over goal X, please don't touch it").
  - Hand-offs that need a read-receipt
    (`message ack <id> <reader>`).
  - Notes-to-self that are time-sensitive but not durable enough
    for a wiki fragment.

== When NOT to use

  - Anything reusable across multiple readers — that's a Wiki entry. An
    acknowledgement changes inbox presentation, not the immutable message;
    Wiki is the durable knowledge surface.
  - Long technical content — messages are conversational. If
    you're writing more than 5 lines, ask whether a fragment
    would serve better.
  - Real-time chat. Message is an append-only same-pile ledger, and the current
    `pile net sync` transport does not yet replicate native collection records.
    Move or concatenate complete pile state through a deployment path that
    understands those records before expecting messages on another node.

== Usage

```sh
# The sender defaults to this active relations identity.
export PERSONA=agent-a # replace with your own relations label

# Send
message send <recipient-handle> "your message"

# List recent (latest first)
message list "$PERSONA"

# Mark as read
message ack <message-id> "$PERSONA"
```

The recipient handle is whatever name maps to a person or agent in the fixed
Relations collection. Message resolves that collection through the same pile
and durable signer as the Message collection; there is no branch selector.

== Collection and storage

Messages live in one fixed, team-rooted Message collection. Each send or
acknowledgement publishes an immutable fragment through an independent signed
COMMIT, so the read history is its own audit trail. Commands accept an existing
durable signing key through `--key` or `TRIBLESPACE_KEY`; ordinary reads and
writes never create one.

Pile concatenation preserves both record sets physically. Current faculty reads
admit only COMMITs made by keys with exact positive WRITE authority, so two
processes share one logical inbox only when they intentionally share the team
root and its authority evidence. Unauthorized COMMITs remain inert evidence
rather than silently becoming trusted messages. Distinct sends by any admitted
authors remain distinct immutable messages; exact retries converge.

== Cross-references

  - "How Faculties Work" — the faculty model
  - "Tool Selection: Faculties First" — when to reach for
    message vs wiki vs compass

Next stop: [Teams: Capability-Based Membership](wiki:67477d2173928fd91ef20173eabfeae4).
