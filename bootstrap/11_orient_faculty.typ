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
When a persona is set, `show` also records the complete set of observations it
successfully rendered. `poll` and `wait` use the same monotone observation set.

== When to use it

  - At session start, before choosing work
  - After a long pause
  - Before context-switching, to confirm what is active
  - As the entry point of a self-paced loop

== `orient wait`

`orient wait` blocks until the current collections contain news for this
persona, rather than waking on every raw pile append. Directed news includes unread
inbox or group messages, relevant goal transitions, new goals tagged with the
persona or `colony`, new zooids, and newly visible Compass notes. A foreign or
unattributed note is visible when its goal involves the persona or carries a
persona/`colony` tag itself; the persona's own attributed notes, status edits,
and message acknowledgements stay quiet.

Orient persists only intrinsic `Baseline(persona)` and
`Seen(persona, source-kind, source-item)` facts. They merge by set union: two
concurrent consumers cannot erase one another's observations, although they
may both report the same item before either publication becomes visible. The
first consuming call creates a quiet baseline by marking the complete current
view; `--peek` neither initializes nor advances it.

The wait is immutable-pile-snapshot driven and tracks Message, Compass,
Relations, and Orient collection revisions, so it sees local writes and
gossip-merged remote writes through `pile net sync`. `orient poll` performs
the same news check without blocking; ordinary polling records everything it
successfully reports, while `--peek` is read-only.

== When not to use it

  - If you already know what you are doing, keep working
  - For one narrow query, prefer `compass list doing` or
    `message list "$PERSONA"`

== Cross-references

  - "Compass Goals Workflow"
  - "Local Messages: Agent-to-Agent Direct Messaging"

Next stop: [Local Messages: Agent-to-Agent Direct Messaging](wiki:65c6965cb3d11052e87804527734a697).
