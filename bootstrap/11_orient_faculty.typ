= Orient: The Situation-Snapshot Faculty

`orient` answers "what is going on in this pile right now?" in one command.
Run it at session start, after a long break, or when you have lost the thread.

== What it shows

`orient show` collates:

  - recent local messages
  - Compass goals in `doing`
  - Compass goals in `todo`
  - current colony status

Defaults to ten messages, five doing goals, and five todo goals. The
`--message-limit`, `--doing-limit`, and `--todo-limit` flags tune those limits.
When a persona is set, `show` also advances that persona's checkpoint used by
`poll` and `wait`.

== When to use it

  - At session start, before choosing work
  - After a long pause
  - Before context-switching, to confirm what is active
  - As the entry point of a self-paced loop

== `orient wait`

`orient wait` blocks until the watched branches contain news for this persona,
rather than waking on every raw branch movement. Directed news includes unread
inbox or group messages, relevant goal transitions, new goals tagged with the
persona or `colony`, and new zooids. The persona's own status edits and message
acknowledgements stay quiet.

The wait is pile-snapshot driven, so it sees local writes and gossip-merged
remote writes through `pile net sync`. `orient poll` performs the same news
check without blocking; `--peek` reports without consuming the checkpoint.

== When not to use it

  - If you already know what you are doing, keep working
  - For one narrow query, prefer `compass list doing` or
    `message list "$PERSONA"`

== Cross-references

  - "Compass Goals Workflow"
  - "Local Messages: Agent-to-Agent Direct Messaging"

Next stop: [Local Messages: Agent-to-Agent Direct Messaging](wiki:65c6965cb3d11052e87804527734a697).
